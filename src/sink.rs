//! Where assembled RTP packets go.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::UdpSocket;

/// A destination for RTP packets. Implementors send each packet (already RTP-framed and
/// encrypted) somewhere — a UDP socket to Discord, an in-memory buffer, a file, etc.
///
/// The packet is borrowed so the [`FramePacer`](crate::pacer::FramePacer) can build every frame in
/// one reused buffer: a real sink writes the bytes to a socket and never needs to own them.
pub trait FrameSink: Send {
    /// Send one packet.
    fn send(&mut self, packet: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}

/// Sends packets over a connected UDP socket (to a Discord voice server).
pub struct UdpFrameSink {
    socket: UdpSocket,
    remote: SocketAddr,
}

impl UdpFrameSink {
    /// Bind a local socket and target `remote`.
    pub async fn connect(local: SocketAddr, remote: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        Ok(Self { socket, remote })
    }

    /// Wrap an already-bound socket.
    pub fn from_socket(socket: UdpSocket, remote: SocketAddr) -> Self {
        Self { socket, remote }
    }
}

impl FrameSink for UdpFrameSink {
    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.socket.send_to(packet, self.remote).await.map(|_| ())
    }
}

/// Collects packets in memory — useful for tests and capture.
#[derive(Debug, Default, Clone)]
pub struct VecSink {
    packets: Arc<Mutex<Vec<Bytes>>>,
}

impl VecSink {
    /// Create an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of the collected packets.
    pub fn packets(&self) -> Vec<Bytes> {
        self.packets.lock().unwrap().clone()
    }

    /// Number of packets collected.
    pub fn len(&self) -> usize {
        self.packets.lock().unwrap().len()
    }

    /// Whether no packets have been collected.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FrameSink for VecSink {
    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.packets
            .lock()
            .unwrap()
            .push(Bytes::copy_from_slice(packet));
        Ok(())
    }
}
