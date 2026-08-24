//! The 20 ms frame pacer, and the single send engine used by both the standalone API and the live
//! [`VoiceConnection`](crate::connection).
//!
//! Each tick it pulls one frame from an [`OpusFrameProvider`], DAVE end-to-end encrypts it via
//! [`DaveEncryptor`], applies the negotiated [`TransportCipher`], RTP-frames it, and hands the
//! finished packet to a [`FrameSink`]. When the provider has nothing, it emits up to
//! [`SILENCE_FRAME_COUNT`] silence frames (so Discord stops cleanly), then goes idle.

use std::io;

use tokio::time::{sleep_until, Instant};

use crate::dave::DaveEncryptor;
use crate::frame::{FRAME_DURATION, OPUS_SILENCE_FRAME, SAMPLES_PER_FRAME, SILENCE_FRAME_COUNT};
use crate::provider::OpusFrameProvider;
use crate::rtp::RtpHeader;
use crate::sink::FrameSink;
use crate::transport::{PlainTransport, TransportCipher};

/// Capacity reserved for the reused packet buffer: RTP header + a worst-case Opus frame (plus the
/// DAVE frame overhead) + AEAD tag + nonce suffix, rounded up under one Ethernet MTU.
const MAX_PACKET_BYTES: usize = 1400;

/// Past three missed slots the clock stops trying to catch up and resynchronises to now, so a long
/// stall doesn't produce a burst of stale frames.
const MAX_CATCHUP_FRAMES: u64 = 3;

/// The 20 ms frame clock.
///
/// Each slot has an **absolute** deadline (`last_frame_time + frame_interval`), not "sleep 20 ms
/// from wherever we are now" — a tick that runs late is followed immediately by the next one instead
/// of pushing the whole schedule out, so lateness never accumulates against Discord's RTP timeline.
/// (`tokio::time::interval` with `MissedTickBehavior::Delay` does accumulate it; `Burst` catches up
/// without bound and `Skip` never catches up at all.) More than `MAX_CATCHUP_FRAMES` behind, the
/// clock gives up on the gap and restarts from now, counting the slots it skipped in
/// [`dropped_frames`](Self::dropped_frames).
pub struct FrameClock {
    next: Instant,
    dropped: u64,
}

impl Default for FrameClock {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameClock {
    /// Start the clock, with the first slot one frame from now.
    pub fn new() -> Self {
        Self {
            next: Instant::now() + FRAME_DURATION,
            dropped: 0,
        }
    }

    /// Wait for the next frame slot, returning how many slots were missed (`0` when on time).
    ///
    /// Cancel-safe: the deadline is absolute and is only advanced after the sleep completes, so
    /// dropping this future (e.g. losing a `select!` race) leaves the cadence untouched.
    pub async fn wait(&mut self) -> u64 {
        let now = Instant::now();
        if now < self.next {
            sleep_until(self.next).await;
            self.next += FRAME_DURATION;
            return 0;
        }

        // Late by truncating division, so being late by less than one whole slot misses nothing and
        // simply runs now.
        let missed = ((now - self.next).as_nanos() / FRAME_DURATION.as_nanos()) as u64;
        self.next = if missed > MAX_CATCHUP_FRAMES {
            tracing::warn!(missed, "voice: frame clock stalled, resynchronising");
            now + FRAME_DURATION
        } else {
            self.next + FRAME_DURATION
        };
        self.dropped = self.dropped.saturating_add(missed);
        missed
    }

    /// Frame slots missed because a tick ran late.
    pub fn dropped_frames(&self) -> u64 {
        self.dropped
    }
}

/// What a single [`FramePacer::tick`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacerStatus {
    /// An audio frame was processed (sent, or dropped because DAVE encryption failed while the
    /// group was active — dropping is correct, never emit plaintext to peers).
    Sent,
    /// A silence frame was sent (draining after audio stopped).
    Silence,
    /// Nothing was sent (no audio and silence already drained).
    Idle,
}

/// Drives an [`OpusFrameProvider`] at a steady 20 ms cadence into a [`FrameSink`], applying DAVE
/// end-to-end encryption and then the transport cipher to every frame.
pub struct FramePacer<P: OpusFrameProvider, S: FrameSink> {
    provider: P,
    sink: S,
    dave: DaveEncryptor,
    transport: Box<dyn TransportCipher>,
    header: RtpHeader,
    /// Reused packet buffer: RTP header + payload, encrypted in place with the tag and nonce
    /// suffix appended. Sized once so the steady-state send path never allocates.
    packet: Vec<u8>,
    silence_left: u8,
    speaking: bool,
    on_speaking: Option<Box<dyn FnMut(bool) + Send>>,
}

impl<P: OpusFrameProvider, S: FrameSink> FramePacer<P, S> {
    /// Create a pacer with **no transport encryption** (local testing only — Discord rejects
    /// unencrypted packets). Use [`with_transport`](Self::with_transport) for a real connection.
    pub fn new(provider: P, sink: S, dave: DaveEncryptor, ssrc: u32) -> Self {
        Self::with_transport(provider, sink, dave, Box::new(PlainTransport), ssrc)
    }

    /// Create a pacer with the negotiated `transport` cipher, for the given SSRC (assigned by
    /// Discord in the voice `READY` payload).
    pub fn with_transport(
        provider: P,
        sink: S,
        dave: DaveEncryptor,
        transport: Box<dyn TransportCipher>,
        ssrc: u32,
    ) -> Self {
        Self {
            provider,
            sink,
            dave,
            transport,
            header: RtpHeader::new(ssrc),
            packet: Vec::with_capacity(MAX_PACKET_BYTES),
            silence_left: 0,
            speaking: false,
            on_speaking: None,
        }
    }

    /// Register a callback invoked when the speaking state changes (send a gateway `SPEAKING`
    /// op from here in a real connection).
    pub fn on_speaking(&mut self, handler: impl FnMut(bool) + Send + 'static) {
        self.on_speaking = Some(Box::new(handler));
    }

    /// Whether the pacer currently considers itself speaking.
    pub fn is_speaking(&self) -> bool {
        self.speaking
    }

    /// Access the DAVE encryptor (e.g. to drive the MLS handshake).
    pub fn dave_mut(&mut self) -> &mut DaveEncryptor {
        &mut self.dave
    }

    /// Process exactly one frame slot (no internal sleep). Callers that want to control timing
    /// themselves can drive this; most should use [`run`](Self::run).
    pub async fn tick(&mut self) -> io::Result<PacerStatus> {
        if let Some(frame) = self.provider.provide() {
            self.set_speaking(true);
            self.silence_left = SILENCE_FRAME_COUNT;
            // `None` => active-group encryption failed; drop the frame rather than leak plaintext.
            if let Some(payload) = self.dave.encrypt(&frame) {
                self.send(&payload).await?;
            }
            Ok(PacerStatus::Sent)
        } else if self.silence_left > 0 {
            // Stop speaking as soon as the silence flush begins; the change-detection in
            // `set_speaking` makes this fire once.
            self.set_speaking(false);
            self.silence_left -= 1;
            if let Some(payload) = self.dave.encrypt(&OPUS_SILENCE_FRAME) {
                self.send(&payload).await?;
            }
            Ok(PacerStatus::Silence)
        } else {
            self.set_speaking(false);
            Ok(PacerStatus::Idle)
        }
    }

    /// Self-paced loop: ticks every 20 ms forever. Spawn this as a task and drop/abort it to
    /// stop. Returns only on a sink I/O error.
    pub async fn run(&mut self) -> io::Result<()> {
        let mut clock = FrameClock::new();
        loop {
            clock.wait().await;
            self.tick().await?;
        }
    }

    /// RTP-frame, transport-encrypt, and send one (already DAVE-processed) payload.
    ///
    /// The whole packet is assembled in [`Self::packet`] and encrypted in place, so a steady-state
    /// frame costs zero allocations.
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let header_bytes = self.header.to_bytes();

        self.packet.clear();
        self.packet.extend_from_slice(&header_bytes);
        self.packet.extend_from_slice(payload);

        // Drop the frame on an AEAD failure: sending the plaintext would leak audio, and this runs
        // on a shared runtime worker where a panic would take unrelated connections down with it.
        if let Err(cause) = self
            .transport
            .encrypt_in_place(&mut self.packet, header_bytes.len())
        {
            tracing::warn!(cause, "voice: transport encryption failed, dropping frame");
        } else {
            self.sink.send(&self.packet).await?;
        }

        self.header.sequence = self.header.sequence.wrapping_add(1);
        self.header.timestamp = self.header.timestamp.wrapping_add(SAMPLES_PER_FRAME);
        Ok(())
    }

    fn set_speaking(&mut self, speaking: bool) {
        if self.speaking != speaking {
            self.speaking = speaking;
            if let Some(handler) = self.on_speaking.as_mut() {
                handler(speaking);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A late slot runs immediately (the deadline stays absolute, so the cadence recovers instead
    /// of drifting), and past `MAX_CATCHUP_FRAMES` the clock gives up on the gap and restarts from
    /// now. Lateness is faked by moving the deadline back rather than by sleeping through it.
    #[tokio::test]
    async fn frame_clock_catches_up_a_late_slot_then_resynchronises() {
        let start = Instant::now();
        let mut clock = FrameClock::new();

        assert_eq!(clock.wait().await, 0);
        assert!(Instant::now() - start >= FRAME_DURATION, "first slot waits");

        // The slot overran by 25 ms: one whole slot missed, and the deadline stays in the past so
        // the catch-up frame runs with no sleep at all.
        clock.next -= FRAME_DURATION * 2 + FRAME_DURATION / 4;
        let late = Instant::now();
        assert_eq!(clock.wait().await, 1);
        assert_eq!(clock.dropped_frames(), 1);
        assert_eq!(
            clock.wait().await,
            0,
            "still behind: no missed slot to count"
        );
        assert!(
            Instant::now() - late < FRAME_DURATION,
            "catch-up slots must not sleep"
        );

        // A long stall: too far behind to make up, so resynchronise rather than burst.
        clock.next -= FRAME_DURATION * 10;
        let missed = clock.wait().await;
        assert!(missed > MAX_CATCHUP_FRAMES, "missed {missed} slots");
        assert_eq!(clock.dropped_frames(), 1 + missed);
        let resumed = Instant::now();
        assert_eq!(clock.wait().await, 0);
        assert!(
            Instant::now() - resumed >= FRAME_DURATION,
            "a full frame after the resync"
        );
    }
}
