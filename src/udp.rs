//! UDP transport to a Discord voice server, including IP discovery.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{timeout_at, Instant};

use crate::sink::FrameSink;

/// How many discovery requests to send before giving up.
const DISCOVERY_ATTEMPTS: u32 = 40;
/// How long to wait for a reply before resending. No audio can leave the node until the handshake
/// finishes, so every dropped datagram costs one of these; `ATTEMPTS * INTERVAL` keeps the overall
/// give-up ceiling at 10 s.
const DISCOVERY_INTERVAL: Duration = Duration::from_millis(250);

/// The external address discovered via Discord's IP discovery handshake.
#[derive(Debug, Clone)]
pub struct DiscoveredAddress {
    /// Public IP address as a string.
    pub ip: String,
    /// Public UDP port.
    pub port: u16,
}

/// A UDP socket connected to a Discord voice server.
pub struct VoiceUdp {
    socket: UdpSocket,
}

impl VoiceUdp {
    /// Bind a local socket and connect it to `remote`.
    pub async fn connect(remote: SocketAddr) -> io::Result<Self> {
        let bind = if remote.is_ipv6() {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(remote).await?;
        Ok(Self { socket })
    }

    /// Send the 74-byte discovery request and parse our public address out of the reply.
    /// See <https://discord.com/developers/docs/topics/voice-connections#ip-discovery>.
    pub async fn discover_ip(&self, ssrc: u32) -> io::Result<DiscoveredAddress> {
        let mut request = [0u8; 74];
        request[0..2].copy_from_slice(&1u16.to_be_bytes()); // type = request
        request[2..4].copy_from_slice(&70u16.to_be_bytes()); // length
        request[4..8].copy_from_slice(&ssrc.to_be_bytes());

        // Oversized so a longer stray datagram reads back as "not 74 bytes" instead of being
        // silently truncated to a plausible-looking response.
        let mut response = [0u8; 128];

        // One dropped packet must not wedge the handshake, so resend and keep reading.
        for attempt in 1..=DISCOVERY_ATTEMPTS {
            self.socket.send(&request).await?;
            let deadline = Instant::now() + DISCOVERY_INTERVAL;

            while let Ok(received) = timeout_at(deadline, self.socket.recv(&mut response)).await {
                if received? == 74 {
                    return Ok(parse_discovery_response(&response));
                }
            }

            tracing::debug!(
                attempt,
                max = DISCOVERY_ATTEMPTS,
                "IP discovery timed out, resending"
            );
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "failed to discover external UDP address",
        ))
    }
}

impl FrameSink for VoiceUdp {
    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.socket.send(packet).await.map(|_| ())
    }
}

/// Parse a 74-byte IP discovery response into its address/port.
pub fn parse_discovery_response(response: &[u8]) -> DiscoveredAddress {
    // Bytes 8..72 hold a null-terminated ASCII IP; bytes 72..74 hold the port (big-endian).
    let addr_end = response[8..72]
        .iter()
        .position(|&b| b == 0)
        .map(|p| 8 + p)
        .unwrap_or(72);
    let ip = String::from_utf8_lossy(&response[8..addr_end]).into_owned();
    let port = u16::from_be_bytes([response[72], response[73]]);
    DiscoveredAddress { ip, port }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_discovery_response() {
        let mut response = [0u8; 74];
        response[0..2].copy_from_slice(&2u16.to_be_bytes());
        response[2..4].copy_from_slice(&70u16.to_be_bytes());
        response[4..8].copy_from_slice(&12345u32.to_be_bytes());
        let ip = b"203.0.113.7";
        response[8..8 + ip.len()].copy_from_slice(ip);
        response[72..74].copy_from_slice(&50000u16.to_be_bytes());

        let parsed = parse_discovery_response(&response);
        assert_eq!(parsed.ip, "203.0.113.7");
        assert_eq!(parsed.port, 50000);
    }

    #[tokio::test]
    async fn discovery_ignores_wrong_sized_packets() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 74);
            assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 4242);

            server.send_to(&[0u8; 8], from).await.unwrap();

            let mut response = [0u8; 74];
            response[0..2].copy_from_slice(&2u16.to_be_bytes());
            response[8..8 + 9].copy_from_slice(b"192.0.2.1");
            response[72..74].copy_from_slice(&41234u16.to_be_bytes());
            server.send_to(&response, from).await.unwrap();
        });

        let client = VoiceUdp::connect(server_addr).await.unwrap();
        let discovered = client.discover_ip(4242).await.unwrap();
        assert_eq!(discovered.ip, "192.0.2.1");
        assert_eq!(discovered.port, 41234);
    }
}
