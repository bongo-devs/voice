//! A live Discord voice connection, orchestrating the gateway WebSocket, UDP transport, DAVE
//! end-to-end encryption, and the 20 ms send loop.
//!
//! Lifecycle: connect the gateway (v8) → `IDENTIFY` → `HELLO`/heartbeat → `READY` (ssrc, udp
//! endpoint, modes) → UDP IP discovery → `SELECT_PROTOCOL` → `SESSION_DESCRIPTION` (mode +
//! secret key + dave protocol version) → spawn the send task ([`FramePacer`] → DAVE → transport
//! → RTP → UDP) and the gateway supervisor (heartbeat, inbound dispatch, resume on disconnect).
//!
//! ## DAVE handling
//! The full DAVE op set is driven here. Binary ops are dispatched to the [`davey`] session,
//! after stripping the per-op wire framing that precedes the raw MLS bytes (see
//! <https://daveprotocol.com/>): 25 `external_sender` → `set_external_sender` + send 26
//! `key_package`; 27 `proposals` (payload `[operation_type: u8][proposals…]`) →
//! `process_proposals` + send 28 `commit_welcome`; 29 `announce_commit_transition` (payload
//! `[transition_id: u16][commit…]`) → `process_commit`; 30 `welcome` (payload
//! `[transition_id: u16][welcome…]`) → `process_welcome`; on a bad commit/welcome we send the
//! JSON op 31 `invalid_commit_welcome` (carrying that transition id) to be re-added. The JSON
//! transition ops drive passthrough/epoch state: 21 `prepare_transition` (reply 23
//! `transition_ready`, enter passthrough on a v0 downgrade), 22 `execute_transition`, 24
//! `prepare_epoch`.
//!
//! [`davey`]: crate::dave::davey
//! [`FramePacer`]: crate::pacer::FramePacer

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::dave::davey::ProposalsOperationType;
use crate::dave::DaveEncryptor;
use crate::event::{EventDispatcher, VoiceEvent, VoiceEventListener};
use crate::pacer::{FrameClock, FramePacer};
use crate::provider::OpusFrameProvider;
use crate::transport::{choose_mode, cipher_for_mode};
use crate::udp::{DiscoveredAddress, VoiceUdp};

mod builders;
mod dave;
mod send_loop;
mod supervisor;

use builders::*;
use dave::*;
use send_loop::*;
use supervisor::*;

/// WebSocket close codes on which Discord's voice gateway can be resumed (op 7). Other codes are
/// treated as fatal — the higher layer should reconnect with fresh voice-server info.
///
/// In order: going away (1001), abnormal closure (1006), internal error (4000), unknown opcode
/// (4001), failed to decode payload (4002), not authenticated (4003), already authenticated (4005),
/// session timeout (4009), unknown protocol (4012), voice server crashed (4015), unknown encryption
/// mode (4016), bad request (4020), and 4900, which this crate raises itself to force a reconnect.
///
/// 4009 in particular is what Discord sends after a heartbeat lapse — a routine network hiccup.
/// Treating it as fatal leaves the guild permanently silent until the client happens to push a new
/// voice update.
const RESUMABLE_CLOSE_CODES: &[u16] = &[
    1001, 1006, 4000, 4001, 4002, 4003, 4005, 4009, 4012, 4015, 4016, 4020, 4900,
];

/// Upper bound on the whole `IDENTIFY` → `SESSION_DESCRIPTION` exchange.
///
/// The caller awaits the handshake inline, so an unbounded wait means no audio for that guild *and*
/// a task leaked with a live WebSocket plus UDP socket. Generous enough to cover a full 10 s
/// IP-discovery retry cycle plus a slow voice region.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How many heartbeat intervals may pass with no op-6 ACK before the gateway is declared dead and
/// resumed. Discord itself closes with 4009 after a heartbeat lapse, so this only fires when the
/// socket is a zombie: it reads fine, but the gateway behind it is gone.
const MISSED_ACKS_BEFORE_DEAD: u32 = 3;

/// How long the gateway supervisor is left alive after [`VoiceConnection::disconnect`] queues the
/// close frame, so it actually reaches Discord before the task is aborted.
const CLOSE_FLUSH_GRACE: Duration = Duration::from_millis(250);

/// Lifecycle state of a [`VoiceConnection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionState {
    /// The initial handshake is in progress.
    Connecting = 0,
    /// Fully connected: gateway live and audio flowing.
    Connected = 1,
    /// The gateway dropped and a resume is being attempted.
    Reconnecting = 2,
    /// Permanently closed (disconnected or a fatal close).
    Closed = 3,
}

impl ConnectionState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => ConnectionState::Connecting,
            1 => ConnectionState::Connected,
            2 => ConnectionState::Reconnecting,
            _ => ConnectionState::Closed,
        }
    }
}

/// Error type for connection establishment.
pub type ConnectError = Box<dyn std::error::Error + Send + Sync>;

// DAVE binary op-codes.
const OP_DAVE_MLS_EXTERNAL_SENDER: u8 = 25;
const OP_DAVE_MLS_KEY_PACKAGE: u8 = 26;
const OP_DAVE_MLS_PROPOSALS: u8 = 27;
const OP_DAVE_MLS_COMMIT_WELCOME: u8 = 28;
const OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION: u8 = 29;
const OP_DAVE_MLS_WELCOME: u8 = 30;
const OP_DAVE_MLS_INVALID_COMMIT_WELCOME: u8 = 31;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = SplitSink<WsStream, Message>;
type WsSource = SplitStream<WsStream>;

/// A DAVE event forwarded from the gateway supervisor to the send task (which owns the session).
enum DaveEvent {
    /// A binary MLS op (25/27/29/30) with its payload.
    Binary { op: u8, payload: Vec<u8> },
    /// Op 21 `DAVE_PREPARE_TRANSITION`.
    PrepareTransition {
        protocol_version: u16,
        transition_id: u64,
    },
    /// Op 22 `DAVE_EXECUTE_TRANSITION`.
    ExecuteTransition { transition_id: u64 },
    /// Op 24 `DAVE_PREPARE_EPOCH`.
    PrepareEpoch { protocol_version: u16, epoch: u64 },
    /// Op 11 `CLIENT_CONNECT` — users the gateway announced.
    UsersConnected { user_ids: Vec<u64> },
    /// Op 13 `CLIENT_DISCONNECT` — a user left.
    UserDisconnected { user_id: u64 },
}

/// Everything needed to join a Discord voice channel — sourced from the main gateway's
/// `VOICE_STATE_UPDATE` (session id) and `VOICE_SERVER_UPDATE` (token, endpoint) events.
#[derive(Debug, Clone)]
pub struct VoiceServerInfo {
    /// Guild (server) id.
    pub guild_id: u64,
    /// Bot user id.
    pub user_id: u64,
    /// Voice channel id (used for the DAVE session).
    pub channel_id: u64,
    /// Voice session id from the main gateway.
    pub session_id: String,
    /// Voice token.
    pub token: String,
    /// Voice server endpoint host (e.g. `"region.discord.media"`), without scheme.
    pub endpoint: String,
}

impl VoiceServerInfo {
    fn ws_url(&self) -> String {
        let host = self
            .endpoint
            .trim_start_matches("wss://")
            .trim_start_matches("ws://");
        format!("wss://{host}/?v=8")
    }
}

/// Re-announces our speaking state whenever a client connects (op 11/12), so clients that join
/// *after* playback began receive our SSRC→user mapping and can render our audio. Without it, late
/// joiners can hear nothing even though frames are flowing. The current speaking flag is kept in
/// sync by the send task's pacer.
#[derive(Clone)]
struct SpeakingReannounce {
    ws_tx: mpsc::UnboundedSender<Message>,
    speaking: Arc<AtomicBool>,
    ssrc: u32,
}

impl SpeakingReannounce {
    fn announce_if_speaking(&self) {
        if self.speaking.load(Ordering::Relaxed) {
            let _ = self.ws_tx.send(speaking_message(true, self.ssrc));
        }
    }
}

/// Parameters needed to resume a dropped voice session (op 7).
struct ResumeInfo {
    url: String,
    server_id: u64,
    session_id: String,
    token: String,
}

/// A live voice connection. Dropping it (or calling [`disconnect`](Self::disconnect)) stops all
/// tasks.
pub struct VoiceConnection {
    ws_tx: mpsc::UnboundedSender<Message>,
    ssrc: u32,
    state: Arc<AtomicU8>,
    /// Last heartbeat round-trip in milliseconds (`u64::MAX` until the first ACK).
    ping: Arc<AtomicU64>,
    /// Shared with the send task's pacer and the op-11/12 re-announce, so an explicit
    /// [`set_speaking`](Self::set_speaking) stays consistent with what gets re-announced.
    speaking: Arc<AtomicBool>,
    dispatcher: EventDispatcher,
    /// The 20 ms send task. Aborted first on disconnect so frames stop immediately.
    sender: Option<JoinHandle<()>>,
    /// The gateway supervisor. Given a short grace period on disconnect so the close frame flushes.
    supervisor: Option<JoinHandle<()>>,
}

impl VoiceConnection {
    /// Connect to a Discord voice server and start streaming frames from `provider`.
    ///
    /// Equivalent to [`connect_with_dispatcher`](Self::connect_with_dispatcher) with no
    /// pre-registered event listeners.
    pub async fn connect<P>(info: VoiceServerInfo, provider: P) -> Result<Self, ConnectError>
    where
        P: OpusFrameProvider + 'static,
    {
        Self::connect_with_dispatcher(info, provider, EventDispatcher::new()).await
    }

    /// Connect to a Discord voice server, dispatching lifecycle [`VoiceEvent`]s to the listeners
    /// pre-registered on `dispatcher`.
    ///
    /// Register listeners *before* calling this: early events ([`GatewayReady`],
    /// [`ExternalIpDiscovered`], [`SessionDescription`]) fire during the handshake, so a listener
    /// added afterwards via [`add_listener`](Self::add_listener) would miss them.
    ///
    /// [`GatewayReady`]: VoiceEvent::GatewayReady
    /// [`ExternalIpDiscovered`]: VoiceEvent::ExternalIpDiscovered
    /// [`SessionDescription`]: VoiceEvent::SessionDescription
    pub async fn connect_with_dispatcher<P>(
        info: VoiceServerInfo,
        provider: P,
        dispatcher: EventDispatcher,
    ) -> Result<Self, ConnectError>
    where
        P: OpusFrameProvider + 'static,
    {
        let state = Arc::new(AtomicU8::new(ConnectionState::Connecting as u8));
        let url = info.ws_url();
        let (ws, _response) = connect_async(url.as_str()).await?;
        let (mut sink, mut stream) = ws.split();

        sink.send(Message::text(identify_message(&info))).await?;

        let mut ssrc = 0u32;
        let mut udp: Option<VoiceUdp> = None;
        let mut chosen_mode: Option<&'static str> = None;
        let mut heartbeat_interval = 41_250.0f64;
        let mut last_seq = 0u64;

        // Created before the handshake so DAVE ops that arrive *during* it are queued rather than
        // dropped: Discord can send op 25 `external_sender` (and the 21/24 transition ops) before
        // `SESSION_DESCRIPTION`, and losing op 25 is unrecoverable — every later welcome then fails
        // with `NoExternalSender`, so the group never activates and every frame is dropped.
        let (dave_tx, dave_rx) = mpsc::unbounded_channel::<DaveEvent>();

        // Drive the handshake until SESSION_DESCRIPTION, yielding the secret key + dave version.
        let handshake = async {
            loop {
                let Some(message) = stream.next().await else {
                    // Surface an abnormal drop as a gateway close rather than a bare error, so the
                    // client still receives a close event for it.
                    dispatcher.dispatch(VoiceEvent::GatewayClosed {
                        code: 1006,
                        reason: "abnormal closure".into(),
                        by_remote: true,
                    });
                    return Err::<(Vec<u8>, u16), ConnectError>(
                        "gateway closed during handshake".into(),
                    );
                };
                let text = match message? {
                    Message::Text(t) => t,
                    Message::Binary(b) => {
                        if b.len() >= 2 {
                            last_seq = last_seq.max(u16::from_be_bytes([b[0], b[1]]) as u64);
                        }
                        forward_dave_binary(&b, &dave_tx);
                        continue;
                    }
                    // A close *during* the handshake carries the diagnosis the caller needs —
                    // 4006 (stale session id), 4009 (session timeout), 4014 (disconnected),
                    // 4004 (auth failed). Dispatch it so it reaches the client instead of being
                    // flattened into an opaque failure.
                    Message::Close(frame) => {
                        let (code, reason) = frame
                            .map(|f| (u16::from(f.code), f.reason.to_string()))
                            .unwrap_or((1006, String::new()));
                        tracing::warn!(code, reason = %reason, "voice: gateway closed during handshake");
                        dispatcher.dispatch(VoiceEvent::GatewayClosed {
                            code,
                            reason: reason.clone(),
                            by_remote: true,
                        });
                        return Err(
                            format!("gateway closed during handshake: {code} {reason}").into()
                        );
                    }
                    _ => continue,
                };
                let value: Value = serde_json::from_str(text.as_str())?;
                if let Some(s) = value["seq"].as_u64() {
                    last_seq = last_seq.max(s);
                }
                let Some(op) = value["op"].as_u64() else {
                    continue;
                };
                // Same routing the supervisor does once it takes over: the 11/13 roster and the
                // 21/22/24 transition ops can land before `SESSION_DESCRIPTION`.
                forward_dave_json(op, &value["d"], &dave_tx);
                match op {
                    8 => {
                        heartbeat_interval = value["d"]["heartbeat_interval"]
                            .as_f64()
                            .unwrap_or(41_250.0);
                    }
                    2 => {
                        let d = &value["d"];
                        ssrc = d["ssrc"].as_u64().ok_or("READY missing ssrc")? as u32;
                        let ip = d["ip"].as_str().ok_or("READY missing ip")?.to_string();
                        let port = d["port"].as_u64().ok_or("READY missing port")? as u16;
                        let offered: Vec<String> = d["modes"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|m| m.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let mode = choose_mode(&offered).ok_or_else(|| {
                            format!("server offered no supported mode: {offered:?}")
                        })?;

                        tracing::info!(ssrc, ip = %ip, port, mode, "voice: gateway READY");
                        dispatcher.dispatch(VoiceEvent::GatewayReady {
                            ssrc,
                            ip: ip.clone(),
                            port,
                        });

                        let remote: SocketAddr = format!("{ip}:{port}").parse()?;
                        let socket = VoiceUdp::connect(remote).await?;
                        let discovered = socket.discover_ip(ssrc).await?;
                        tracing::info!(
                            ip = %discovered.ip,
                            port = discovered.port,
                            "voice: external address discovered"
                        );
                        dispatcher.dispatch(VoiceEvent::ExternalIpDiscovered {
                            ip: discovered.ip.clone(),
                            port: discovered.port,
                        });
                        sink.send(Message::text(select_protocol_message(&discovered, mode)))
                            .await?;
                        chosen_mode = Some(mode);
                        udp = Some(socket);
                    }
                    4 => {
                        let key: Vec<u8> = value["d"]["secret_key"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|n| n.as_u64().map(|x| x as u8))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let version =
                            value["d"]["dave_protocol_version"].as_u64().unwrap_or(0) as u16;
                        return Ok((key, version));
                    }
                    _ => {}
                }
            }
        };
        let (secret_key, dave_version): (Vec<u8>, u16) =
            match timeout(HANDSHAKE_TIMEOUT, handshake).await {
                Ok(result) => result?,
                Err(_) => return Err("voice handshake timed out".into()),
            };

        let udp = udp.ok_or("never received READY")?;
        let mode = chosen_mode.ok_or("never received READY")?;
        if dave_version == 0 {
            tracing::info!(
                mode,
                "voice: session established (DAVE disabled, transport-only)"
            );
        } else {
            tracing::info!(
                mode,
                dave_protocol_version = dave_version,
                "voice: session established, negotiating DAVE end-to-end encryption"
            );
        }
        dispatcher.dispatch(VoiceEvent::SessionDescription {
            mode: mode.to_string(),
            dave_protocol_version: dave_version,
        });
        let transport = cipher_for_mode(mode, &secret_key).map_err(ConnectError::from)?;
        let mut dave = DaveEncryptor::new(info.user_id, info.channel_id)?;

        let (ws_tx, ws_rx) = mpsc::unbounded_channel::<Message>();

        // DAVE enabled: send our MLS key package up front, so the gateway has it before it issues
        // the add proposals/commit that put us in the group. Queued on the outbound channel, it
        // flushes as soon as the gateway task starts pumping.
        if dave_version > 0 {
            send_key_package(&mut dave, &ws_tx);
        }
        // Send-only connection: ask the SFU for no inbound media at all.
        let _ = ws_tx.send(media_sink_wants_message());
        // Shared speaking flag: the send task keeps it in sync, the gateway task reads it to
        // re-announce speaking when a client connects.
        let speaking = Arc::new(AtomicBool::new(false));

        // Publish `Connected` *before* the tasks exist: a gateway close that lands immediately
        // stores `Closed` from the supervisor, and storing `Connected` afterwards would overwrite
        // it — leaving `send_loop` pacing frames at 50 fps into a dead socket forever (its only
        // exit is observing `Closed`) and `is_connected` reporting a live connection.
        state.store(ConnectionState::Connected as u8, Ordering::SeqCst);
        tracing::info!(ssrc, "voice: connected, audio send loop running");

        let sender = tokio::spawn(send_loop(
            provider,
            udp,
            dave,
            transport,
            ssrc,
            ws_tx.clone(),
            dave_rx,
            dispatcher.clone(),
            speaking.clone(),
            state.clone(),
        ));

        let resume = ResumeInfo {
            url,
            server_id: info.guild_id,
            session_id: info.session_id,
            token: info.token,
        };
        let ping = Arc::new(AtomicU64::new(u64::MAX));
        let reannounce = SpeakingReannounce {
            ws_tx: ws_tx.clone(),
            speaking: speaking.clone(),
            ssrc,
        };
        let supervisor = tokio::spawn(gateway_loop(
            resume,
            sink,
            stream,
            ws_rx,
            dave_tx,
            heartbeat_interval,
            last_seq,
            state.clone(),
            ping.clone(),
            dispatcher.clone(),
            reannounce,
        ));

        Ok(Self {
            ws_tx,
            ssrc,
            state,
            ping,
            speaking,
            dispatcher,
            sender: Some(sender),
            supervisor: Some(supervisor),
        })
    }

    /// The connection SSRC.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The last voice-gateway heartbeat round-trip latency in milliseconds, or `None` if no
    /// heartbeat has been acknowledged yet.
    pub fn ping(&self) -> Option<u64> {
        match self.ping.load(Ordering::Relaxed) {
            u64::MAX => None,
            value => Some(value),
        }
    }

    /// The current lifecycle [`ConnectionState`].
    pub fn state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::SeqCst))
    }

    /// The event dispatcher driving this connection's [`VoiceEvent`]s.
    pub fn dispatcher(&self) -> &EventDispatcher {
        &self.dispatcher
    }

    /// Register a listener for ongoing [`VoiceEvent`]s. Listeners added here will *not* receive
    /// handshake events already emitted before [`connect`](Self::connect) returned — pass a
    /// pre-populated dispatcher to [`connect_with_dispatcher`](Self::connect_with_dispatcher) to
    /// catch those.
    pub fn add_listener(&self, listener: Arc<dyn VoiceEventListener>) {
        self.dispatcher.register(listener);
    }

    /// Announce speaking state to the gateway.
    pub fn set_speaking(&self, speaking: bool) {
        // Keep the shared flag in step with the announcement: the op-11/12 re-announce reads it, so
        // a stale `true` here would tell every late joiner we are speaking after we stopped.
        self.speaking.store(speaking, Ordering::Relaxed);
        let _ = self.ws_tx.send(speaking_message(speaking, self.ssrc));
    }

    /// Disconnect: close the gateway and stop all tasks.
    pub fn disconnect(mut self) {
        self.state
            .store(ConnectionState::Closed as u8, Ordering::SeqCst);
        let _ = self.ws_tx.send(close_message());
        // Stop the audio immediately — the caller may already be handing this guild's frames to a
        // replacement connection, and two send tasks on one SSRC interleave RTP sequence numbers.
        if let Some(sender) = self.sender.take() {
            sender.abort();
        }
        // The supervisor still has to pump the queued close frame out of `ws_tx`, so give it a
        // moment before pulling the rug out. Off-runtime callers just abort now.
        let Some(supervisor) = self.supervisor.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    sleep(CLOSE_FLUSH_GRACE).await;
                    supervisor.abort();
                });
            }
            Err(_) => supervisor.abort(),
        }
    }
}

impl Drop for VoiceConnection {
    fn drop(&mut self) {
        for task in [self.sender.take(), self.supervisor.take()]
            .into_iter()
            .flatten()
        {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(endpoint: &str) -> VoiceServerInfo {
        VoiceServerInfo {
            guild_id: 1,
            user_id: 2,
            channel_id: 3,
            session_id: "s".into(),
            token: "t".into(),
            endpoint: endpoint.into(),
        }
    }

    #[test]
    fn builds_v8_ws_url_and_strips_scheme() {
        assert_eq!(
            info("region.discord.media").ws_url(),
            "wss://region.discord.media/?v=8"
        );
        assert_eq!(
            info("wss://region.discord.media").ws_url(),
            "wss://region.discord.media/?v=8"
        );
    }

    #[test]
    fn dave_binary_framing_is_op_then_payload() {
        let msg = dave_binary(OP_DAVE_MLS_KEY_PACKAGE, b"kp");
        let data = msg.into_data();
        assert_eq!(data[0], OP_DAVE_MLS_KEY_PACKAGE); // op first, no seq prefix
        assert_eq!(&data[1..], b"kp");
    }

    #[test]
    fn proposals_payload_splits_optype_from_mls_bytes() {
        // op-27 payload (after seq+op) is `[operation_type][proposals…]`; the optype byte must be
        // stripped before the MLS bytes reach davey, or TLS deserialization fails.
        let (op, mls) = split_proposals(&[0x00, 0xDE, 0xAD]).unwrap();
        assert_eq!(op, ProposalsOperationType::APPEND);
        assert_eq!(mls, &[0xDE, 0xAD]);

        let (op, mls) = split_proposals(&[0x01, 0xBE, 0xEF]).unwrap();
        assert_eq!(op, ProposalsOperationType::REVOKE);
        assert_eq!(mls, &[0xBE, 0xEF]);

        assert!(split_proposals(&[]).is_none()); // empty
        assert!(split_proposals(&[0x07]).is_none()); // unknown operation type
    }

    #[test]
    fn transition_id_is_stripped_from_commit_and_welcome() {
        // op-29/op-30 payloads (after seq+op) are `[transition_id: u16 BE][mls…]`.
        let (id, mls) = strip_transition_id(&[0x00, 0x05, 0xAA, 0xBB]).unwrap();
        assert_eq!(id, 5);
        assert_eq!(mls, &[0xAA, 0xBB]);

        // A bare transition id with no MLS bytes is still valid framing.
        let (id, mls) = strip_transition_id(&[0x01, 0x00]).unwrap();
        assert_eq!(id, 256);
        assert!(mls.is_empty());

        assert!(strip_transition_id(&[0x00]).is_none()); // too short for a u16 id
    }

    #[test]
    fn invalid_commit_welcome_is_op31_json_with_transition_id() {
        let value: Value = serde_json::from_str(
            invalid_commit_welcome_message(42)
                .into_text()
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(value["op"], 31);
        assert_eq!(value["d"]["transition_id"], 42);
    }

    #[test]
    fn heartbeat_is_v8_shape_with_seq_ack() {
        let msg = heartbeat_message(7, 42);
        let text = msg.into_text().unwrap();
        let value: Value = serde_json::from_str(text.as_str()).unwrap();
        assert_eq!(value["op"], 3);
        assert_eq!(value["d"]["t"], 7);
        assert_eq!(value["d"]["seq_ack"], 42);
    }

    #[test]
    fn resume_uses_op7_with_seq_ack() {
        let resume = ResumeInfo {
            url: "wss://x/?v=8".into(),
            server_id: 99,
            session_id: "sid".into(),
            token: "tok".into(),
        };
        let value: Value =
            serde_json::from_str(resume_message(&resume, 12).into_text().unwrap().as_str())
                .unwrap();
        assert_eq!(value["op"], 7);
        assert_eq!(value["d"]["server_id"], "99");
        assert_eq!(value["d"]["session_id"], "sid");
        assert_eq!(value["d"]["seq_ack"], 12);
    }

    #[test]
    fn transition_ready_is_op23() {
        let value: Value =
            serde_json::from_str(transition_ready_message(5).into_text().unwrap().as_str())
                .unwrap();
        assert_eq!(value["op"], 23);
        assert_eq!(value["d"]["transition_id"], 5);
    }

    #[test]
    fn resumable_close_codes_only() {
        // Codes in the resumable set, plus an abnormal drop with no frame, are resumable.
        for &code in RESUMABLE_CLOSE_CODES {
            assert!(is_resumable(Some(code)), "{code} should resume");
        }
        assert!(is_resumable(None), "abnormal drop should resume");
        // A heartbeat lapse (4009) must resume, not be treated as fatal.
        assert!(is_resumable(Some(4009)));
        // Fatal: 4004 auth failed, 4006 session no longer valid, 4011 server not found,
        // 4014 disconnected, 4021 rate limited, 4022 all clients disconnected.
        for code in [1000u16, 4004, 4006, 4011, 4014, 4021, 4022] {
            assert!(!is_resumable(Some(code)), "{code} should be fatal");
        }
    }

    #[test]
    fn connection_state_round_trips() {
        for state in [
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Reconnecting,
            ConnectionState::Closed,
        ] {
            assert_eq!(ConnectionState::from_u8(state as u8), state);
        }
    }

    #[test]
    fn dave_ops_are_routed_to_the_send_task() {
        // The handshake and the supervisor share this routing: DAVE ops that land before
        // SESSION_DESCRIPTION must reach the send task, or a dropped op 25 leaves every later
        // welcome failing with `NoExternalSender` and the group never activates.
        let (tx, mut rx) = mpsc::unbounded_channel::<DaveEvent>();

        // `[seq: u16 BE][op][mls…]` — the seq and op bytes are stripped, the MLS bytes are not.
        forward_dave_binary(&[0x00, 0x07, OP_DAVE_MLS_EXTERNAL_SENDER, 0xAB], &tx);
        forward_dave_binary(&[0x00, 0x08, 99, 0xCD], &tx); // not a DAVE op
        forward_dave_binary(&[0x00], &tx); // too short to carry an op
        forward_dave_json(11, &json!({ "user_ids": ["4", "5"] }), &tx);
        forward_dave_json(13, &json!({ "user_id": "4" }), &tx);
        forward_dave_json(
            21,
            &json!({ "protocol_version": 1, "transition_id": 3 }),
            &tx,
        );
        forward_dave_json(22, &json!({ "transition_id": 3 }), &tx);
        forward_dave_json(24, &json!({ "protocol_version": 1, "epoch": 1 }), &tx);
        forward_dave_json(6, &json!({}), &tx); // heartbeat ack is not a DAVE op
        drop(tx);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        assert_eq!(events.len(), 6, "one event per DAVE op, nothing else");
        assert!(matches!(
            &events[0],
            DaveEvent::Binary { op: OP_DAVE_MLS_EXTERNAL_SENDER, payload } if payload == &[0xAB]
        ));
        assert!(
            matches!(&events[1], DaveEvent::UsersConnected { user_ids } if user_ids == &[4, 5])
        );
        assert!(matches!(
            events[2],
            DaveEvent::UserDisconnected { user_id: 4 }
        ));
        assert!(matches!(
            events[3],
            DaveEvent::PrepareTransition {
                protocol_version: 1,
                transition_id: 3
            }
        ));
        assert!(matches!(
            events[4],
            DaveEvent::ExecuteTransition { transition_id: 3 }
        ));
        assert!(matches!(
            events[5],
            DaveEvent::PrepareEpoch {
                protocol_version: 1,
                epoch: 1
            }
        ));
    }

    #[test]
    fn resume_backoff_grows_and_stays_bounded() {
        // Every connection on a host drops together when a voice server cycles, so the delay must
        // grow and carry jitter — but stay inside the gateway's own session-resume window.
        let delays: Vec<Duration> = (0..5).map(backoff_delay).collect();
        for pair in delays.windows(2) {
            assert!(pair[1] > pair[0], "{:?} must grow", delays);
        }
        assert!(delays[0] >= Duration::from_millis(500));
        assert!(*delays.last().unwrap() <= Duration::from_millis(8_500));
    }

    #[test]
    fn local_close_is_normal_closure_and_sink_wants_nothing() {
        let Message::Close(Some(frame)) = close_message() else {
            panic!("expected a close frame");
        };
        assert_eq!(u16::from(frame.code), 1000);

        let value: Value =
            serde_json::from_str(media_sink_wants_message().into_text().unwrap().as_str()).unwrap();
        assert_eq!(value["op"], 15);
        assert_eq!(value["d"]["any"], 0);
    }
}
