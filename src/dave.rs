//! DAVE end-to-end encryption for Opus frames, backed by the [`davey`] crate.
//! Frames pass through unchanged until an MLS group is negotiated, then they are encrypted.

use std::num::NonZeroU16;

use bytes::Bytes;
use davey::{DaveSession, SessionStatus};

/// Re-export of davey so consumers can drive the MLS handshake with matching types.
pub use davey;

/// The newest protocol version davey speaks, rejected at compile time if it were ever zero.
const PROTOCOL_VERSION: NonZeroU16 = match NonZeroU16::new(davey::DAVE_PROTOCOL_VERSION) {
    Some(version) => version,
    None => panic!("DAVE_PROTOCOL_VERSION must be non-zero"),
};

/// Applies DAVE end-to-end encryption to Opus frames via [`davey::DaveSession`].
pub struct DaveEncryptor {
    session: DaveSession,
}

impl DaveEncryptor {
    /// Create a DAVE session for a Discord user and channel at the latest protocol version.
    pub fn new(user_id: u64, channel_id: u64) -> Result<Self, davey::errors::InitError> {
        Ok(Self {
            session: DaveSession::new(PROTOCOL_VERSION, user_id, channel_id, None)?,
        })
    }

    /// End-to-end encrypt one frame, or pass it through before a group exists. `None` means the
    /// group is active but encryption failed, so the caller must drop the frame.
    pub fn encrypt(&mut self, packet: &[u8]) -> Option<Bytes> {
        match self.session.encrypt_opus(packet) {
            // `Owned` once the group is active, `Borrowed` during passthrough, so `into_owned()`
            // moves the ciphertext into `Bytes` without a copy in the steady state.
            Ok(encrypted) => Some(Bytes::from(encrypted.into_owned())),
            Err(_) if !self.session.is_ready() => Some(Bytes::copy_from_slice(packet)),
            Err(_) => None,
        }
    }

    /// Re-initialise the session for a new MLS group, Discord's new-epoch re-key.
    /// Without it the new group's proposals fail with `Wrong Epoch` or `AlreadyInGroup`.
    pub fn reinit(&mut self) -> Result<(), davey::errors::ReinitError> {
        let version = self.session.protocol_version();
        let user_id = self.session.user_id();
        let channel_id = self.session.channel_id();
        self.session.reinit(version, user_id, channel_id, None)
    }

    /// Enable or disable passthrough mode (used during DAVE transitions / downgrades). When
    /// disabling, davey applies the default ~10 s transition grace period.
    pub fn set_passthrough(&mut self, enabled: bool) {
        self.session.set_passthrough_mode(enabled, None);
    }

    /// Tear down the MLS group and clear key material, for a downgrade to DAVE v0.
    /// Afterwards the session is INACTIVE and frames pass through unencrypted.
    pub fn reset(&mut self) {
        if let Err(error) = self.session.reset() {
            tracing::warn!(%error, "DAVE: failed to reset session");
        }
    }

    /// Borrow the underlying session (read-only).
    pub fn session(&self) -> &DaveSession {
        &self.session
    }

    /// Mutably borrow the session to drive the MLS handshake (`set_external_sender`,
    /// `create_key_package`, `process_proposals`, `process_commit`, `process_welcome`, ...).
    pub fn session_mut(&mut self) -> &mut DaveSession {
        &mut self.session
    }

    /// Current session status.
    pub fn status(&self) -> SessionStatus {
        self.session.status()
    }

    /// Whether the session can end-to-end encrypt yet.
    pub fn is_ready(&self) -> bool {
        self.session.is_ready()
    }

    /// The 30-digit voice privacy code, once a group is established.
    pub fn voice_privacy_code(&self) -> Option<&str> {
        self.session.voice_privacy_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reinit_resets_a_fresh_session() {
        // A fresh session has no group: reinit (with no external sender) resets cleanly and the
        // session stays not-ready / non-ACTIVE, ready to be onboarded into a new group.
        let mut encryptor = DaveEncryptor::new(1234, 5678).expect("create session");
        assert!(!encryptor.is_ready());

        encryptor.reinit().expect("reinit a fresh session");

        assert!(!encryptor.is_ready());
        assert_ne!(encryptor.status(), SessionStatus::ACTIVE);
    }

    #[test]
    fn reset_leaves_session_inactive() {
        // reset() (the DAVE v0-downgrade path) tears down any group; a fresh session is already
        // groupless, so it stays not-ready and INACTIVE without erroring.
        let mut encryptor = DaveEncryptor::new(1234, 5678).expect("create session");
        encryptor.reset();
        assert!(!encryptor.is_ready());
        assert_eq!(encryptor.status(), SessionStatus::INACTIVE);
    }

    #[test]
    fn passes_frames_through_before_a_group_exists() {
        let mut encryptor = DaveEncryptor::new(1234, 5678).expect("create session");
        let frame = b"opus-frame-bytes";
        assert_eq!(encryptor.encrypt(frame).expect("passthrough"), &frame[..]);
    }
}
