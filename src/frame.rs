//! Voice frame constants.

use std::time::Duration;

/// Duration of one voice frame (20 ms).
pub const FRAME_DURATION: Duration = Duration::from_millis(20);

/// Opus samples per frame at 48 kHz (20 ms).
pub const SAMPLES_PER_FRAME: u32 = 960;

/// The Discord Opus silence frame, sent to flush the encoder / signal end of speech.
pub const OPUS_SILENCE_FRAME: [u8; 3] = [0xF8, 0xFF, 0xFE];

/// Number of silence frames Discord recommends sending after audio stops.
pub const SILENCE_FRAME_COUNT: u8 = 5;
