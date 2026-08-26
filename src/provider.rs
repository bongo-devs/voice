//! The producer/consumer contract between whatever encodes audio and the send layer.

use bytes::Bytes;

/// Source of 20 ms Opus frames, polled once per frame slot by the pacer.
///
/// ```
/// use voice::OpusFrameProvider;
///
/// let mut frames = vec![bytes::Bytes::from_static(b"opus")];
/// let mut provider = move || frames.pop();
/// assert!(provider.provide().is_some());
/// assert!(provider.provide().is_none());
/// ```
pub trait OpusFrameProvider: Send {
    /// Next Opus frame, or `None` if none is ready. Must not block.
    fn provide(&mut self) -> Option<Bytes>;
}

impl<F: FnMut() -> Option<Bytes> + Send> OpusFrameProvider for F {
    fn provide(&mut self) -> Option<Bytes> {
        self()
    }
}
