//! RTP packetization for Discord voice (RFC 3550 header + Opus payload).

/// First header byte: RTP version 2, no padding/extension/CSRC.
pub const RTP_VERSION_FLAGS: u8 = 0x80;
/// Discord's Opus payload type.
pub const PAYLOAD_TYPE_OPUS: u8 = 0x78;
/// RTP header length in bytes.
pub const RTP_HEADER_LEN: usize = 12;

/// A 12-byte RTP header, mirroring the layout Discord expects.
#[derive(Debug, Clone, Copy)]
pub struct RtpHeader {
    /// Per-packet sequence number (wraps at 16 bits).
    pub sequence: u16,
    /// Sample timestamp (increments by 960 per 20 ms frame).
    pub timestamp: u32,
    /// Synchronization source, assigned by Discord in the voice `READY` payload.
    pub ssrc: u32,
}

impl RtpHeader {
    /// A header for `ssrc` with the sequence and timestamp at zero.
    pub fn new(ssrc: u32) -> Self {
        Self {
            sequence: 0,
            timestamp: 0,
            ssrc,
        }
    }

    /// The 12 header bytes.
    pub fn to_bytes(&self) -> [u8; RTP_HEADER_LEN] {
        let mut buf = [0u8; RTP_HEADER_LEN];
        buf[0] = RTP_VERSION_FLAGS;
        buf[1] = PAYLOAD_TYPE_OPUS;
        buf[2..4].copy_from_slice(&self.sequence.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        let header = RtpHeader {
            sequence: 0x0102,
            timestamp: 0x0304_0506,
            ssrc: 0x0708_090A,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes[0], RTP_VERSION_FLAGS);
        assert_eq!(bytes[1], PAYLOAD_TYPE_OPUS);
        assert_eq!(&bytes[2..4], &[0x01, 0x02]);
        assert_eq!(&bytes[4..8], &[0x03, 0x04, 0x05, 0x06]);
        assert_eq!(&bytes[8..12], &[0x07, 0x08, 0x09, 0x0A]);
    }
}
