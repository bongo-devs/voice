//! The producer/consumer contract between whatever encodes audio and the send layer.

use bytes::Bytes;

/// Source of 20 ms Opus frames, polled once per frame slot by the
/// [`FramePacer`](crate::pacer::FramePacer).
///
/// `None` means "nothing to send right now" and is not an error: the pacer drains its silence
/// frames and goes idle until frames reappear. Implementations must not block — this is called
/// from the send loop on every 20 ms tick.
///
/// Any `FnMut() -> Option<Bytes>` closure implements this, so a producer can be adapted inline:
///
/// ```
/// use bytes::Bytes;
/// use voice::OpusFrameProvider;
///
/// let mut frames = vec![Bytes::from_static(b"opus")];
/// let mut provider = move || frames.pop();
/// assert!(provider.provide().is_some());
/// assert!(provider.provide().is_none());
/// ```
pub trait OpusFrameProvider: Send {
    /// Next Opus frame, or `None` if none is ready.
    fn provide(&mut self) -> Option<Bytes>;
}

/// Any frame-returning closure is a provider, so producers can be adapted without a named type.
impl<F: FnMut() -> Option<Bytes> + Send> OpusFrameProvider for F {
    fn provide(&mut self) -> Option<Bytes> {
        self()
    }
}
