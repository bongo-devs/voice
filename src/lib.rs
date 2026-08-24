//! Discord voice send layer: pulls 20 ms Opus frames from a producer, wraps them in RTP, encrypts
//! them, and sends them to Discord over UDP.
