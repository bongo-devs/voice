//! # voice
//!
//! The Discord voice send layer: a producer hands over 20 ms Opus frames, and this crate pulls them
//! at a steady 20 ms cadence, wraps them in RTP, encrypts them, and sends them to Discord over UDP.
//!
//! ```text
//!   ┌─────────────────────────────────┐
//!   │  OpusFrameProvider              │
//!   │      │ provide() (20ms Opus)    │
//!   │      ▼                          │
//!   │  FramePacer (20ms clock)        │
//!   │      │ DAVE + transport + RTP   │
//!   │      ▼                          │
//!   │  FrameSink ──▶ UDP/Discord      │
//!   └─────────────────────────────────┘
//! ```
//!
//! End-to-end encryption is **DAVE** ([`dave`], backed by the [`davey`](https://docs.rs/davey)
//! crate) — Discord's current MLS-based voice encryption — layered over the required AEAD transport
//! ciphers ([`transport`]: `aead_aes256_gcm_rtpsize` and `aead_xchacha20_poly1305_rtpsize`).
//!
//! Implemented here: the producer/consumer [`provider`] contract, DAVE encryption via [`dave`],
//! [`rtp`] packetization, the unified 20 ms [`pacer`] (DAVE → transport → RTP → sink), pluggable
//! [`sink`]s (UDP + in-memory), and a live [`connection`] that drives the v8 WebSocket, UDP IP
//! discovery, the full DAVE MLS handshake + transitions (ops 21–31), heartbeats with `seq_ack`,
//! and resume-on-disconnect.

pub mod connection;
pub mod dave;
pub mod event;
pub mod frame;
pub mod pacer;
pub mod provider;
pub mod rtp;
pub mod sink;
pub mod transport;
pub mod udp;

pub use connection::{ConnectionState, VoiceConnection, VoiceServerInfo};
pub use dave::DaveEncryptor;
pub use event::{EventDispatcher, VoiceEvent, VoiceEventAdapter, VoiceEventListener};
pub use frame::{OPUS_SILENCE_FRAME, SAMPLES_PER_FRAME, SILENCE_FRAME_COUNT};
pub use pacer::{FramePacer, PacerStatus};
pub use provider::OpusFrameProvider;
pub use rtp::RtpHeader;
pub use sink::{FrameSink, UdpFrameSink, VecSink};
pub use transport::{
    choose_mode, cipher_for_mode, select_cipher, AesGcmRtpSize, PlainTransport, TransportCipher,
    XChaCha20Poly1305RtpSize,
};
pub use udp::{DiscoveredAddress, VoiceUdp};
