//! The Discord voice send layer: a producer hands over 20 ms Opus frames, and this crate paces,
//! encrypts, RTP-frames, and sends them over UDP, with DAVE end-to-end encryption on top.

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
