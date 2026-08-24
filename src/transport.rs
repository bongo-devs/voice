//! Transport-layer encryption for the voice UDP packets.
//!
//! Discord requires the RTP payload to be encrypted on the wire. This is **separate from and
//! below** DAVE end-to-end encryption: the Opus frame is first DAVE-encrypted, then the result
//! is transport-encrypted here before being placed after the RTP header.
//!
//! Two AEAD `_rtpsize` modes are implemented:
//! - [`AesGcmRtpSize`] — `aead_aes256_gcm_rtpsize` (preferred when the platform has AES
//!   hardware), 12-byte nonce.
//! - [`XChaCha20Poly1305RtpSize`] — `aead_xchacha20_poly1305_rtpsize`, the mode every client is
//!   required to support, 24-byte nonce.
//!
//! In both modes the nonce is a 32-bit big-endian counter in the first 4 bytes (rest zero), the
//! RTP header is the AEAD associated data, the 16-byte tag follows the ciphertext, and the 4-byte
//! counter is appended as the packet suffix so the receiver can reconstruct the nonce.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use chacha20poly1305::{Key as XKey, XChaCha20Poly1305, XNonce};

/// Encrypts an RTP payload for transport, in place, inside the packet buffer.
pub trait TransportCipher: Send {
    /// The negotiated mode's wire name.
    fn mode(&self) -> &'static str;

    /// Encrypt the payload region of `packet` — everything from `header_len` onwards — using
    /// `packet[..header_len]` (the RTP header) as associated data, then append the 16-byte tag and
    /// the 4-byte nonce suffix. On return `packet` is the complete wire packet.
    ///
    /// Returns `Err` if the AEAD refuses the input. The caller must **drop the frame**, never send
    /// it: emitting the plaintext would leak audio, and a panic here would take down the shared
    /// runtime worker (koe logs and drops instead).
    fn encrypt_in_place(
        &mut self,
        packet: &mut Vec<u8>,
        header_len: usize,
    ) -> Result<(), &'static str>;
}

/// Build the next `N`-byte AEAD nonce from a 32-bit counter (counter in the first 4 bytes,
/// big-endian, the rest zero), returning the nonce bytes and the 4-byte suffix to append.
fn rtpsize_nonce<const N: usize>(counter: u32) -> ([u8; N], [u8; 4]) {
    let mut nonce = [0u8; N];
    let suffix = counter.to_be_bytes();
    nonce[..4].copy_from_slice(&suffix);
    (nonce, suffix)
}

/// `aead_aes256_gcm_rtpsize` transport encryption.
pub struct AesGcmRtpSize {
    cipher: Aes256Gcm,
    nonce_counter: u32,
}

impl AesGcmRtpSize {
    /// The wire name of this mode.
    pub const MODE: &'static str = "aead_aes256_gcm_rtpsize";

    /// Create a cipher from Discord's 32-byte secret key.
    pub fn new(secret_key: &[u8]) -> Result<Self, &'static str> {
        let cipher = Aes256Gcm::new_from_slice(secret_key)
            .map_err(|_| "secret key must be 32 bytes for AES-256-GCM")?;
        Ok(Self {
            cipher,
            nonce_counter: 0,
        })
    }
}

impl TransportCipher for AesGcmRtpSize {
    fn mode(&self) -> &'static str {
        Self::MODE
    }

    fn encrypt_in_place(
        &mut self,
        packet: &mut Vec<u8>,
        header_len: usize,
    ) -> Result<(), &'static str> {
        let counter = self.nonce_counter;
        self.nonce_counter = self.nonce_counter.wrapping_add(1);

        let (nonce_bytes, suffix) = rtpsize_nonce::<12>(counter);
        let (aad, msg) = packet.split_at_mut(header_len);
        let tag = self
            .cipher
            .encrypt_in_place_detached(GcmNonce::from_slice(&nonce_bytes), aad, msg)
            .map_err(|_| "AES-GCM encryption failed")?;
        packet.extend_from_slice(tag.as_slice());
        packet.extend_from_slice(&suffix);
        Ok(())
    }
}

/// `aead_xchacha20_poly1305_rtpsize` transport encryption — the mandatory-to-support mode.
pub struct XChaCha20Poly1305RtpSize {
    cipher: XChaCha20Poly1305,
    nonce_counter: u32,
}

impl XChaCha20Poly1305RtpSize {
    /// The wire name of this mode.
    pub const MODE: &'static str = "aead_xchacha20_poly1305_rtpsize";

    /// Create a cipher from Discord's 32-byte secret key.
    pub fn new(secret_key: &[u8]) -> Result<Self, &'static str> {
        if secret_key.len() != 32 {
            return Err("secret key must be 32 bytes for XChaCha20-Poly1305");
        }
        Ok(Self {
            cipher: XChaCha20Poly1305::new(XKey::from_slice(secret_key)),
            nonce_counter: 0,
        })
    }
}

impl TransportCipher for XChaCha20Poly1305RtpSize {
    fn mode(&self) -> &'static str {
        Self::MODE
    }

    fn encrypt_in_place(
        &mut self,
        packet: &mut Vec<u8>,
        header_len: usize,
    ) -> Result<(), &'static str> {
        let counter = self.nonce_counter;
        self.nonce_counter = self.nonce_counter.wrapping_add(1);

        let (nonce_bytes, suffix) = rtpsize_nonce::<24>(counter);
        let (aad, msg) = packet.split_at_mut(header_len);
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce_bytes), aad, msg)
            .map_err(|_| "XChaCha20-Poly1305 encryption failed")?;
        packet.extend_from_slice(tag.as_slice());
        packet.extend_from_slice(&suffix);
        Ok(())
    }
}

/// Choose a transport mode from the ones the server offered, preferring AES-256-GCM (hardware
/// accelerated where available) and falling back to the always-supported XChaCha20-Poly1305.
/// Returns the chosen mode's wire name (to announce in `SELECT_PROTOCOL`).
pub fn choose_mode(modes: &[String]) -> Option<&'static str> {
    if modes.iter().any(|m| m == AesGcmRtpSize::MODE) {
        Some(AesGcmRtpSize::MODE)
    } else if modes.iter().any(|m| m == XChaCha20Poly1305RtpSize::MODE) {
        Some(XChaCha20Poly1305RtpSize::MODE)
    } else {
        None
    }
}

/// Build the cipher for an already-chosen mode wire name and the 32-byte secret key.
pub fn cipher_for_mode(mode: &str, secret_key: &[u8]) -> Result<Box<dyn TransportCipher>, String> {
    match mode {
        AesGcmRtpSize::MODE => AesGcmRtpSize::new(secret_key)
            .map(|c| Box::new(c) as Box<dyn TransportCipher>)
            .map_err(String::from),
        XChaCha20Poly1305RtpSize::MODE => XChaCha20Poly1305RtpSize::new(secret_key)
            .map(|c| Box::new(c) as Box<dyn TransportCipher>)
            .map_err(String::from),
        other => Err(format!("unsupported encryption mode: {other}")),
    }
}

/// Pick and build a transport cipher for the offered modes (combines [`choose_mode`] and
/// [`cipher_for_mode`]).
pub fn select_cipher(
    modes: &[String],
    secret_key: &[u8],
) -> Result<Box<dyn TransportCipher>, String> {
    match choose_mode(modes) {
        Some(mode) => cipher_for_mode(mode, secret_key),
        None => Err(format!(
            "server offered no supported encryption mode: {modes:?}"
        )),
    }
}

/// No transport encryption (local testing only — never accepted by Discord).
#[derive(Debug, Default, Clone, Copy)]
pub struct PlainTransport;

impl TransportCipher for PlainTransport {
    fn mode(&self) -> &'static str {
        "plaintext"
    }

    fn encrypt_in_place(
        &mut self,
        _packet: &mut Vec<u8>,
        _header_len: usize,
    ) -> Result<(), &'static str> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, Payload};

    /// Build the packet buffer the pacer hands to the cipher: header followed by payload.
    fn packet_of(header: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(header.len() + payload.len() + 20);
        packet.extend_from_slice(header);
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn aes_gcm_rtpsize_roundtrip() {
        let key = [7u8; 32];
        let header = [
            0x80, 0x78, 0x00, 0x01, 0, 0, 0x03, 0xC0, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let payload = b"opus-payload-bytes";

        let mut cipher = AesGcmRtpSize::new(&key).unwrap();
        let mut packet = packet_of(&header, payload);
        cipher.encrypt_in_place(&mut packet, header.len()).unwrap();

        // The header must survive untouched, and the 4-byte counter suffix must trail the tag.
        assert_eq!(&packet[..header.len()], &header);
        assert_eq!(packet.len(), header.len() + payload.len() + 16 + 4);

        let (ct_and_tag, suffix) = packet[header.len()..].split_at(packet.len() - header.len() - 4);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(suffix);

        let dec = Aes256Gcm::new_from_slice(&key).unwrap();
        let plain = dec
            .decrypt(
                GcmNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ct_and_tag,
                    aad: &header,
                },
            )
            .unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn xchacha_rtpsize_roundtrip() {
        let key = [9u8; 32];
        let header = [
            0x80, 0x78, 0x00, 0x02, 0, 0, 0x07, 0x80, 0xCA, 0xFE, 0xBA, 0xBE,
        ];
        let payload = b"another-opus-frame";

        let mut cipher = XChaCha20Poly1305RtpSize::new(&key).unwrap();
        let mut packet = packet_of(&header, payload);
        cipher.encrypt_in_place(&mut packet, header.len()).unwrap();

        assert_eq!(&packet[..header.len()], &header);

        let (ct_and_tag, suffix) = packet[header.len()..].split_at(packet.len() - header.len() - 4);
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes[..4].copy_from_slice(suffix);

        let dec = XChaCha20Poly1305::new(XKey::from_slice(&key));
        let plain = dec
            .decrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ct_and_tag,
                    aad: &header,
                },
            )
            .unwrap();
        assert_eq!(plain, payload);
    }

    /// The nonce counter must advance per frame, so two identical frames encrypt differently.
    #[test]
    fn nonce_counter_advances_per_frame() {
        let mut cipher = AesGcmRtpSize::new(&[3u8; 32]).unwrap();
        let header = [0x80, 0x78, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];

        let mut first = packet_of(&header, b"frame");
        cipher.encrypt_in_place(&mut first, header.len()).unwrap();
        let mut second = packet_of(&header, b"frame");
        cipher.encrypt_in_place(&mut second, header.len()).unwrap();

        assert_ne!(first, second);
        assert_eq!(&first[first.len() - 4..], &0u32.to_be_bytes());
        assert_eq!(&second[second.len() - 4..], &1u32.to_be_bytes());
    }

    #[test]
    fn select_prefers_gcm_then_xchacha() {
        let key = [0u8; 32];
        let both = vec![
            "aead_xchacha20_poly1305_rtpsize".to_string(),
            "aead_aes256_gcm_rtpsize".to_string(),
        ];
        assert_eq!(
            select_cipher(&both, &key).unwrap().mode(),
            AesGcmRtpSize::MODE
        );

        let xchacha_only = vec!["aead_xchacha20_poly1305_rtpsize".to_string()];
        assert_eq!(
            select_cipher(&xchacha_only, &key).unwrap().mode(),
            XChaCha20Poly1305RtpSize::MODE
        );

        let none = vec!["xsalsa20_poly1305".to_string()];
        assert!(select_cipher(&none, &key).is_err());
    }
}
