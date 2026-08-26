# voice

Discord voice send layer in Rust. It pulls 20 ms Opus frames from a producer, wraps them in RTP,
encrypts them with DAVE and the negotiated transport cipher, and sends them to Discord over UDP.

## Features

- Voice gateway v8: `IDENTIFY` / `RESUME` with `seq_ack`, heartbeat ACK watchdog, and
  resume-on-disconnect with exponential backoff
- UDP IP discovery (with retries) and RTP packetization
- Transport AEAD: `aead_aes256_gcm_rtpsize` and `aead_xchacha20_poly1305_rtpsize`
- DAVE end-to-end encryption — MLS, gateway ops 21–31 — including protocol and epoch transitions,
  and recovery from an invalid commit or welcome
- 20 ms pacer on absolute per-slot deadlines, with silence-frame draining and speaking announcements
- Event listeners for the connection lifecycle

## Usage

```toml
[dependencies]
voice = "0.1"
```

Anything that yields 20 ms Opus frames is a source: implement
[`OpusFrameProvider`](src/provider.rs), or just pass a `FnMut() -> Option<Bytes>` closure.

```rust
use bytes::Bytes;
use voice::{VoiceConnection, VoiceServerInfo};

let mut frames: Vec<Bytes> = encode_opus_somehow();
let provider = move || frames.pop();

let connection = VoiceConnection::connect(
    VoiceServerInfo {
        guild_id,
        user_id,
        channel_id,
        // session_id comes from VOICE_STATE_UPDATE; token and endpoint from VOICE_SERVER_UPDATE.
        session_id,
        token,
        endpoint,
    },
    provider,
)
.await?;

println!("ssrc {} ping {:?}", connection.ssrc(), connection.ping());
```

Register listeners with `VoiceConnection::connect_with_dispatcher` to observe the handshake —
listeners added later miss the events that fire during it.

## Modules

| Module       | What it does                                                       |
| ------------ | ------------------------------------------------------------------ |
| `connection` | The live gateway connection: WebSocket, DAVE handshake, send task   |
| `pacer`      | The 20 ms frame clock and the send engine                          |
| `provider`   | The producer/consumer contract for Opus frames                     |
| `dave`       | DAVE end-to-end encryption, backed by `davey`                      |
| `transport`  | The transport AEAD ciphers                                         |
| `rtp`        | The RTP header                                                     |
| `udp`        | The UDP socket and IP discovery                                    |
| `sink`       | Where finished packets go (UDP, or in-memory for tests)            |
| `event`      | Connection events and listener dispatch                            |

## Credits

The voice gateway connection logic in this crate is derived from
[koe](https://github.com/KyokoBot/koe) by Alula — the connection lifecycle and handshake
sequencing, the resumable close-code set, the DAVE/MLS op handling and transition flow, and the
speaking re-announce behaviour all follow koe's design, reimplemented in Rust. koe is MIT licensed
(Copyright (c) 2019 Alula); its full notice is reproduced in [LICENSE](LICENSE).

Also relied on:

- [davey](https://github.com/Snazzah/davey) — the Rust DAVE/MLS implementation this crate depends on.
- [The DAVE protocol](https://daveprotocol.com/) — Discord's specification for end-to-end encrypted
  voice.

## License

MIT — see [LICENSE](LICENSE), which also carries the third-party notice for koe.
