//! Discord voice send layer: pulls 20 ms Opus frames from a producer, wraps them in RTP, encrypts
//! them, and sends them to Discord over UDP.

pub mod dave;
pub mod event;
pub mod frame;
pub mod provider;
pub mod rtp;
pub mod sink;
pub mod transport;
pub mod udp;

pub use dave::DaveEncryptor;
pub use event::{EventDispatcher, VoiceEvent, VoiceEventAdapter, VoiceEventListener};
pub use frame::{OPUS_SILENCE_FRAME, SAMPLES_PER_FRAME, SILENCE_FRAME_COUNT};
pub use provider::OpusFrameProvider;
pub use rtp::RtpHeader;
pub use sink::{FrameSink, UdpFrameSink, VecSink};
pub use transport::{
    choose_mode, cipher_for_mode, select_cipher, AesGcmRtpSize, PlainTransport, TransportCipher,
    XChaCha20Poly1305RtpSize,
};
pub use udp::{DiscoveredAddress, VoiceUdp};
