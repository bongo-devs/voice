use super::builders::{heartbeat_message, identify_message, resume_message};
use super::*;

/// Resume budget across closes: a confirmed session (op 4 or op 9) restores it.
struct ReconnectBudget {
    attempts: u32,
}

impl ReconnectBudget {
    fn new() -> Self {
        Self { attempts: 0 }
    }

    /// The session description arrived or a resume was acknowledged: the budget is whole again.
    fn confirm(&mut self) {
        self.attempts = 0;
    }

    fn can_attempt(&self) -> bool {
        self.attempts < MAX_RECONNECT_ATTEMPTS
    }

    fn record_attempt(&mut self) {
        self.attempts += 1;
    }

    fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// Which handshake a reconnect performs: op 7 while the session is believed alive, otherwise a
/// fresh op 0 that rebuilds the session from scratch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionMode {
    Resume,
    Identify,
}

/// What one close should do, given the session state and the remaining budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseDecision {
    /// Reconnect with the current session mode.
    Reconnect,
    /// The gateway forgot the session: reconnect fresh once, then report if it drops again.
    ReconnectFresh,
    /// Fatal, or the budget is exhausted: report the close and stop.
    Report,
}

fn close_decision(code: Option<u16>, mode: SessionMode, can_attempt: bool) -> CloseDecision {
    if code == Some(SESSION_NO_LONGER_VALID) {
        return match (mode, can_attempt) {
            (SessionMode::Resume, true) => CloseDecision::ReconnectFresh,
            _ => CloseDecision::Report,
        };
    }
    if is_resumable(code) && can_attempt {
        CloseDecision::Reconnect
    } else {
        CloseDecision::Report
    }
}

/// The op-7 / op-0 payload a reconnect sends for the current mode.
fn reconnect_message(session: &SessionInfo, mode: SessionMode, last_seq: u64) -> Message {
    match mode {
        SessionMode::Resume => resume_message(session, last_seq),
        SessionMode::Identify => Message::text(identify_message(session)),
    }
}

/// Gateway supervisor: owns the WebSocket, heartbeats, dispatches inbound ops, and resumes on a
/// dropped connection while the send task (UDP/DAVE) keeps running.
#[allow(clippy::too_many_arguments)]
pub(super) async fn gateway_loop(
    session: SessionInfo,
    mut sink: WsSink,
    mut stream: WsSource,
    mut ws_rx: mpsc::UnboundedReceiver<Message>,
    dave_tx: mpsc::UnboundedSender<DaveEvent>,
    heartbeat_interval_ms: f64,
    mut last_seq: u64,
    ssrc: Arc<AtomicU32>,
    state: Arc<AtomicU8>,
    ping: Arc<AtomicU64>,
    dispatcher: EventDispatcher,
    reannounce: SpeakingReannounce,
) {
    let period = Duration::from_millis(heartbeat_interval_ms.max(1.0) as u64);
    // The first beat follows a full interval; HELLO re-arms the schedule on every connection.
    let mut hb = interval_at(tokio::time::Instant::now() + period, period);
    let mut mode = SessionMode::Resume;
    // A fresh session's UDP link, negotiated on READY and handed to the send task on op 4.
    let mut pending: Option<PendingLink> = None;
    let mut budget = ReconnectBudget::new();
    // The handshake's session description starts the budget at zero; this covers op 4/op 9 mid-loop.
    let mut session_confirmed = false;

    loop {
        let outcome = pump(
            &mut sink,
            &mut stream,
            &mut ws_rx,
            &dave_tx,
            &dispatcher,
            &reannounce,
            &mut hb,
            &mut last_seq,
            &ping,
            &state,
            &mut session_confirmed,
            &mut mode,
            &mut pending,
            &ssrc,
        )
        .await;
        if session_confirmed {
            session_confirmed = false;
            budget.confirm();
        }

        match outcome {
            // We initiated the close (the connection was disconnected/dropped).
            PumpOutcome::Stop => {
                state.store(ConnectionState::Closed as u8, Ordering::SeqCst);
                break;
            }
            // The gateway dropped: resume on a resumable close code, otherwise treat it as fatal.
            PumpOutcome::Closed {
                code,
                reason,
                by_remote,
            } => {
                // `disconnect` and the send loop giving up both store `Closed` before the close
                // frame goes out, so a local stop is neither resumed nor reported.
                if ConnectionState::from_u8(state.load(Ordering::SeqCst)) == ConnectionState::Closed
                {
                    tracing::debug!(code = code.unwrap_or(0), "voice: gateway closed locally");
                    break;
                }
                let decision = close_decision(code, mode, budget.can_attempt());
                let mut recovered = false;
                if decision != CloseDecision::Report {
                    if decision == CloseDecision::ReconnectFresh {
                        mode = SessionMode::Identify;
                    }
                    // Only reconnect if still Connected; a concurrent `disconnect` sets Closed, and
                    // resuming would revive a connection the caller asked to drop.
                    let claimed = state
                        .compare_exchange(
                            ConnectionState::Connected as u8,
                            ConnectionState::Reconnecting as u8,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok();
                    if !claimed {
                        // `disconnect` raced in after the drop; flush its queued close and stop.
                        let _ = sink.send(Message::Close(None)).await;
                        return;
                    }
                    tracing::warn!(
                        code = code.unwrap_or(1006),
                        attempt = budget.attempts() + 1,
                        budget = MAX_RECONNECT_ATTEMPTS,
                        fresh = mode == SessionMode::Identify,
                        "voice: gateway dropped, reconnecting"
                    );
                    // Attempts run back to back: the gateway restores sessions for a short window,
                    // so the delay itself is the risk.
                    while budget.can_attempt() {
                        // Nothing pumps `ws_rx` during this loop, so a `disconnect` queued there is
                        // invisible; watch the state and flush the close frame ourselves instead of
                        // leaking the session until Discord times it out.
                        if ConnectionState::from_u8(state.load(Ordering::SeqCst))
                            == ConnectionState::Closed
                        {
                            let _ = sink.send(Message::Close(None)).await;
                            return;
                        }
                        budget.record_attempt();
                        if let Ok((new_sink, new_stream)) = reconnect(&session.url).await {
                            sink = new_sink;
                            stream = new_stream;
                            if sink
                                .send(reconnect_message(&session, mode, last_seq))
                                .await
                                .is_ok()
                            {
                                recovered = true;
                                break;
                            }
                        }
                    }
                } else if (is_resumable(code) || code == Some(SESSION_NO_LONGER_VALID))
                    && !budget.can_attempt()
                {
                    tracing::warn!(
                        attempts = budget.attempts(),
                        "voice: reconnect budget exhausted, reporting the close to the client"
                    );
                }
                if recovered {
                    tracing::info!("voice: gateway reconnected");
                    state.store(ConnectionState::Connected as u8, Ordering::SeqCst);
                } else {
                    // An abnormal drop has no code of its own; report it as one.
                    let code = code.unwrap_or(1006);
                    tracing::warn!(
                        code,
                        reason = %reason,
                        by_remote,
                        "voice: gateway closed"
                    );
                    state.store(ConnectionState::Closed as u8, Ordering::SeqCst);
                    dispatcher.dispatch(VoiceEvent::GatewayClosed {
                        code,
                        reason,
                        by_remote,
                    });
                    break;
                }
            }
        }
    }
}

/// Whether a WebSocket close should trigger a resume. A missing code (an abnormal drop with no
/// close frame, e.g. 1006-style) is treated as resumable.
pub(super) fn is_resumable(code: Option<u16>) -> bool {
    match code {
        Some(code) => RESUMABLE_CLOSE_CODES.contains(&code),
        None => true,
    }
}

/// Outcome of one [`pump`] over a single WebSocket lifetime.
enum PumpOutcome {
    /// The outbound channel closed (the connection was disconnected or dropped), so stop entirely.
    Stop,
    /// The WebSocket closed or errored. [`is_resumable`] decides resume-vs-fatal from `code`.
    Closed {
        /// The close code, if a close frame was received.
        code: Option<u16>,
        /// The close reason text (empty if none).
        reason: String,
        /// Whether the remote (Discord) initiated the close.
        by_remote: bool,
    },
}

/// Follow-up work an inbound message asks the pump to run (it owns the WebSocket and DAVE channel).
enum Inbound {
    /// No follow-up.
    None,
    /// Op 2 `READY`: negotiate the fresh session's UDP link.
    FreshReady(ReadyVoice),
    /// Op 4 `SESSION_DESCRIPTION`: swap the pending link into the send task.
    FreshSession {
        /// Transport encryption secret.
        key: Vec<u8>,
        /// DAVE protocol version negotiated for this session.
        dave_protocol_version: u16,
    },
    /// The message makes the session unusable.
    Fatal(String),
}

/// Drive one WebSocket until it drops or the outbound channel closes.
#[allow(clippy::too_many_arguments)]
async fn pump(
    sink: &mut WsSink,
    stream: &mut WsSource,
    ws_rx: &mut mpsc::UnboundedReceiver<Message>,
    dave_tx: &mpsc::UnboundedSender<DaveEvent>,
    dispatcher: &EventDispatcher,
    reannounce: &SpeakingReannounce,
    hb: &mut tokio::time::Interval,
    last_seq: &mut u64,
    ping: &Arc<AtomicU64>,
    state: &Arc<AtomicU8>,
    session_confirmed: &mut bool,
    mode: &mut SessionMode,
    pending: &mut Option<PendingLink>,
    ssrc: &Arc<AtomicU32>,
) -> PumpOutcome {
    // When the last heartbeat was sent, used to compute the round-trip on the matching ACK (op 6).
    let mut last_heartbeat: Option<Instant> = None;
    loop {
        tokio::select! {
            outbound = ws_rx.recv() => match outbound {
                Some(message) => {
                    if sink.send(message).await.is_err() {
                        return PumpOutcome::Closed {
                            code: None,
                            reason: "outbound send failed".into(),
                            by_remote: false,
                        };
                    }
                }
                None => {
                    let _ = sink.send(Message::Close(None)).await;
                    return PumpOutcome::Stop;
                }
            },
            _ = hb.tick() => {
                if sink
                    .send(heartbeat_message(*last_seq))
                    .await
                    .is_err()
                {
                    return PumpOutcome::Closed {
                        code: None,
                        reason: "heartbeat send failed".into(),
                        by_remote: false,
                    };
                }
                last_heartbeat = Some(Instant::now());
            },
            inbound = stream.next() => match inbound {
                Some(Ok(Message::Close(frame))) => return close_outcome(frame),
                Some(Ok(message)) => {
                    match handle_inbound(
                        message,
                        dave_tx,
                        dispatcher,
                        reannounce,
                        state,
                        last_seq,
                        ping,
                        last_heartbeat,
                        session_confirmed,
                        hb,
                        pending,
                    ) {
                        Inbound::None => {}
                        Inbound::FreshReady(ready) => {
                            let negotiated = establish_link(
                                sink,
                                dispatcher,
                                ready.ssrc,
                                &ready.ip,
                                ready.port,
                                &ready.modes,
                            )
                            .await;
                            match negotiated {
                                Ok((udp, negotiated_mode)) => {
                                    ssrc.store(ready.ssrc, Ordering::Relaxed);
                                    *mode = SessionMode::Resume;
                                    *pending = Some(PendingLink {
                                        udp,
                                        mode: negotiated_mode,
                                    });
                                }
                                Err(error) => {
                                    dispatcher.dispatch(VoiceEvent::GatewayError {
                                        message: error.to_string(),
                                    });
                                    return PumpOutcome::Closed {
                                        code: None,
                                        reason: "session renegotiation failed".into(),
                                        by_remote: false,
                                    };
                                }
                            }
                        }
                        Inbound::FreshSession {
                            key,
                            dave_protocol_version,
                        } => {
                            let Some(link) = pending.take() else {
                                return PumpOutcome::Closed {
                                    code: None,
                                    reason: "session description without a selected protocol".into(),
                                    by_remote: false,
                                };
                            };
                            let transport = match cipher_for_mode(link.mode, &key) {
                                Ok(transport) => transport,
                                Err(error) => {
                                    dispatcher.dispatch(VoiceEvent::GatewayError {
                                        message: error.clone(),
                                    });
                                    return PumpOutcome::Closed {
                                        code: None,
                                        reason: error,
                                        by_remote: false,
                                    };
                                }
                            };
                            let _ = dave_tx.send(DaveEvent::FreshSession {
                                udp: link.udp,
                                transport,
                                ssrc: ssrc.load(Ordering::Relaxed),
                                dave_protocol_version,
                            });
                            dispatcher.dispatch(VoiceEvent::SessionDescription {
                                mode: link.mode.to_string(),
                                dave_protocol_version,
                            });
                        }
                        Inbound::Fatal(reason) => {
                            dispatcher.dispatch(VoiceEvent::GatewayError {
                                message: reason.clone(),
                            });
                            return PumpOutcome::Closed {
                                code: None,
                                reason,
                                by_remote: false,
                            };
                        }
                    }
                }
                Some(Err(error)) => {
                    dispatcher.dispatch(VoiceEvent::GatewayError {
                        message: error.to_string(),
                    });
                    return PumpOutcome::Closed {
                        code: Some(4000),
                        reason: "Internal error".into(),
                        by_remote: false,
                    };
                }
                None => {
                    return PumpOutcome::Closed {
                        code: None,
                        reason: "Abnormal closure".into(),
                        by_remote: false,
                    };
                }
            },
        }
    }
}

/// Translate a WebSocket close frame into a [`PumpOutcome`].
fn close_outcome(frame: Option<CloseFrame>) -> PumpOutcome {
    match frame {
        Some(frame) => PumpOutcome::Closed {
            code: Some(u16::from(frame.code)),
            reason: frame.reason.to_string(),
            by_remote: true,
        },
        None => PumpOutcome::Closed {
            code: None,
            reason: String::new(),
            by_remote: true,
        },
    }
}

/// Track the server sequence, forward DAVE ops, and report follow-up work the pump must run.
#[allow(clippy::too_many_arguments)]
fn handle_inbound(
    message: Message,
    dave_tx: &mpsc::UnboundedSender<DaveEvent>,
    dispatcher: &EventDispatcher,
    reannounce: &SpeakingReannounce,
    state: &Arc<AtomicU8>,
    last_seq: &mut u64,
    ping: &Arc<AtomicU64>,
    last_heartbeat: Option<Instant>,
    session_confirmed: &mut bool,
    hb: &mut tokio::time::Interval,
    pending: &Option<PendingLink>,
) -> Inbound {
    match message {
        // Binary header: seq (2, BE) + op (1) + MLS payload.
        Message::Binary(bytes) => {
            if bytes.len() >= 2 {
                *last_seq = (*last_seq).max(u16::from_be_bytes([bytes[0], bytes[1]]) as u64);
            }
            forward_dave_binary(&bytes, dave_tx);
            Inbound::None
        }
        Message::Text(text) => {
            let Ok(value) = serde_json::from_str::<Value>(text.as_str()) else {
                return Inbound::None;
            };
            if let Some(s) = value["seq"].as_u64() {
                *last_seq = (*last_seq).max(s);
            }
            let d = &value["d"];
            let Some(op) = value["op"].as_u64() else {
                return Inbound::None;
            };
            forward_dave_json(op, d, dave_tx);
            match op {
                // Op 2 `READY`: a fresh session; its UDP link must be negotiated before op 4 keys it.
                2 => match ready_from_payload(d) {
                    Ok(ready) => Inbound::FreshReady(ready),
                    Err(error) => Inbound::Fatal(error),
                },
                // Op 4 `SESSION_DESCRIPTION`: restores the budget, re-announces speaking, and
                // switches in the fresh link when one was negotiated.
                4 => {
                    *session_confirmed = true;
                    reannounce.announce_if_speaking();
                    if pending.is_some() {
                        Inbound::FreshSession {
                            key: session_secret_key(d),
                            dave_protocol_version: session_dave_version(d),
                        }
                    } else {
                        Inbound::None
                    }
                }
                // Op 6 `HEARTBEAT_ACK`: record the round-trip since the last heartbeat as the ping.
                6 => {
                    if let Some(sent) = last_heartbeat {
                        ping.store(sent.elapsed().as_millis() as u64, Ordering::Relaxed);
                    }
                    Inbound::None
                }
                // Op 8 `HELLO`: (re)arm the heartbeat schedule for this connection.
                8 => {
                    if let Some(ms) = d["heartbeat_interval"].as_f64() {
                        let period = Duration::from_millis(ms.max(1.0) as u64);
                        *hb = interval_at(tokio::time::Instant::now() + period, period);
                    }
                    Inbound::None
                }
                // Op 9 `RESUMED`: mark the session connected again and restore the reconnect budget.
                9 => {
                    tracing::info!("voice: gateway session resumed (RESUMED)");
                    state.store(ConnectionState::Connected as u8, Ordering::SeqCst);
                    *session_confirmed = true;
                    Inbound::None
                }
                // Op 11 `CLIENT_CONNECT`: a batch of `user_ids` that joined. The voice gateway does
                // not carry their audio SSRCs here, so report 0.
                11 => {
                    if let Some(ids) = d["user_ids"].as_array() {
                        for user_id in ids.iter().filter_map(|v| v.as_str()) {
                            dispatcher.dispatch(VoiceEvent::UserConnected {
                                user_id: user_id.to_string(),
                                audio_ssrc: 0,
                            });
                        }
                    }
                    Inbound::None
                }
                // Op 12 `VIDEO`: a single user's stream SSRCs changed; re-announce so late joiners
                // map our SSRC and hear us.
                12 => {
                    if let Some(user_id) = d["user_id"].as_str() {
                        dispatcher.dispatch(VoiceEvent::UserConnected {
                            user_id: user_id.to_string(),
                            audio_ssrc: d["audio_ssrc"].as_u64().unwrap_or(0) as u32,
                        });
                    }
                    reannounce.announce_if_speaking();
                    Inbound::None
                }
                // Op 13 `CLIENT_DISCONNECT`.
                13 => {
                    if let Some(user_id) = d["user_id"].as_str() {
                        dispatcher.dispatch(VoiceEvent::UserDisconnected {
                            user_id: user_id.to_string(),
                        });
                    }
                    Inbound::None
                }
                _ => Inbound::None,
            }
        }
        _ => Inbound::None,
    }
}

/// Forward a binary MLS op (`[seq: u16 BE][op: u8][mls…]`) to the send task, which owns the DAVE
/// session. Also called during the handshake, since op 25 can precede `SESSION_DESCRIPTION`.
pub(super) fn forward_dave_binary(bytes: &[u8], dave_tx: &mpsc::UnboundedSender<DaveEvent>) {
    if bytes.len() < 3 {
        return;
    }
    let op = bytes[2];
    if matches!(
        op,
        OP_DAVE_MLS_EXTERNAL_SENDER
            | OP_DAVE_MLS_PROPOSALS
            | OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION
            | OP_DAVE_MLS_WELCOME
    ) {
        let _ = dave_tx.send(DaveEvent::Binary {
            op,
            payload: bytes[3..].to_vec(),
        });
    }
}

/// Forward the DAVE-relevant JSON ops to the send task: the 11/13 roster (which MLS Add proposals
/// are validated against) and the 21/22/24 transition ops. Also shared with the handshake.
pub(super) fn forward_dave_json(op: u64, d: &Value, dave_tx: &mpsc::UnboundedSender<DaveEvent>) {
    match op {
        11 => {
            let user_ids: Vec<u64> = d["user_ids"]
                .as_array()
                .map(|ids| {
                    ids.iter()
                        .filter_map(|v| v.as_str()?.parse().ok())
                        .collect()
                })
                .unwrap_or_default();
            if !user_ids.is_empty() {
                let _ = dave_tx.send(DaveEvent::UsersConnected { user_ids });
            }
        }
        13 => {
            if let Some(user_id) = d["user_id"].as_str().and_then(|id| id.parse().ok()) {
                let _ = dave_tx.send(DaveEvent::UserDisconnected { user_id });
            }
        }
        21 => {
            let _ = dave_tx.send(DaveEvent::PrepareTransition {
                protocol_version: d["protocol_version"].as_u64().unwrap_or(0) as u16,
                transition_id: d["transition_id"].as_u64().unwrap_or(0),
            });
        }
        22 => {
            let _ = dave_tx.send(DaveEvent::ExecuteTransition {
                transition_id: d["transition_id"].as_u64().unwrap_or(0),
            });
        }
        24 => {
            let _ = dave_tx.send(DaveEvent::PrepareEpoch {
                protocol_version: d["protocol_version"].as_u64().unwrap_or(0) as u16,
                epoch: d["epoch"].as_u64().unwrap_or(0),
            });
        }
        _ => {}
    }
}

pub(super) async fn reconnect(url: &str) -> Result<(WsSink, WsSource), ConnectError> {
    let (ws, _response) = match timeout(CONNECT_TIMEOUT, connect_async(url)).await {
        Ok(result) => result?,
        Err(_) => return Err("voice gateway reconnect timed out".into()),
    };
    Ok(ws.split())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionInfo {
        SessionInfo {
            url: "wss://x/?v=8".into(),
            server_id: 1,
            user_id: 2,
            channel_id: 3,
            session_id: "s".into(),
            token: "t".into(),
        }
    }

    // Three successful reconnects in a row must not exhaust the budget.
    #[test]
    fn confirmed_reconnects_never_exhaust_the_budget() {
        let mut budget = ReconnectBudget::new();
        for _ in 0..3 {
            assert!(budget.can_attempt());
            budget.record_attempt();
            budget.confirm();
        }
        assert!(
            budget.can_attempt(),
            "a confirmed session restores the budget"
        );
        assert_eq!(budget.attempts(), 0);
    }

    #[test]
    fn unconfirmed_attempts_exhaust_the_budget() {
        let mut budget = ReconnectBudget::new();
        for _ in 0..MAX_RECONNECT_ATTEMPTS {
            assert!(budget.can_attempt());
            budget.record_attempt();
        }
        assert!(
            !budget.can_attempt(),
            "attempts without a confirmed session run out"
        );
    }

    #[test]
    fn session_invalid_close_attempts_one_fresh_identify() {
        assert_eq!(
            close_decision(Some(4006), SessionMode::Resume, true),
            CloseDecision::ReconnectFresh
        );
        assert_eq!(
            close_decision(Some(4006), SessionMode::Resume, false),
            CloseDecision::Report
        );
        assert_eq!(
            close_decision(Some(4006), SessionMode::Identify, true),
            CloseDecision::Report,
            "a second 4006 is fatal"
        );
    }

    #[test]
    fn resumable_codes_reconnect_and_fatal_codes_report() {
        assert_eq!(
            close_decision(None, SessionMode::Resume, true),
            CloseDecision::Reconnect
        );
        assert_eq!(
            close_decision(Some(1006), SessionMode::Resume, true),
            CloseDecision::Reconnect
        );
        assert_eq!(
            close_decision(Some(4009), SessionMode::Identify, true),
            CloseDecision::Reconnect
        );
        assert_eq!(
            close_decision(Some(1006), SessionMode::Resume, false),
            CloseDecision::Report
        );
        assert_eq!(
            close_decision(Some(4004), SessionMode::Resume, true),
            CloseDecision::Report
        );
        assert_eq!(
            close_decision(Some(1000), SessionMode::Resume, true),
            CloseDecision::Report
        );
    }

    #[test]
    fn reconnects_use_resume_or_identify_per_mode() {
        let value: Value = serde_json::from_str(
            reconnect_message(&session(), SessionMode::Resume, 3)
                .into_text()
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(value["op"], 7);
        assert_eq!(value["d"]["seq_ack"], 3);

        let value: Value = serde_json::from_str(
            reconnect_message(&session(), SessionMode::Identify, 3)
                .into_text()
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(value["op"], 0);
        assert_eq!(value["d"]["channel_id"], "3");
    }

    // Op 4 and op 9 both confirm the session, which is what restores the budget.
    #[tokio::test]
    async fn session_description_and_resumed_confirm_the_session() {
        for op in [4u64, 9] {
            let (dave_tx, _dave_rx) = mpsc::unbounded_channel();
            let dispatcher = EventDispatcher::new();
            let (speak_tx, _speak_rx) = mpsc::unbounded_channel();
            let reannounce = SpeakingReannounce {
                ws_tx: speak_tx,
                speaking: Arc::new(AtomicBool::new(false)),
                ssrc: Arc::new(AtomicU32::new(0)),
            };
            let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
            let ping = Arc::new(AtomicU64::new(0));
            let mut last_seq: u64 = 0;
            let mut confirmed = false;
            let mut hb = interval_at(
                tokio::time::Instant::now() + Duration::from_secs(60),
                Duration::from_secs(60),
            );
            let payload = format!(r#"{{"op":{op},"d":{{}}}}"#);

            let inbound = handle_inbound(
                Message::text(payload),
                &dave_tx,
                &dispatcher,
                &reannounce,
                &state,
                &mut last_seq,
                &ping,
                None,
                &mut confirmed,
                &mut hb,
                &None,
            );

            assert!(matches!(inbound, Inbound::None));
            assert!(confirmed, "op {op} must confirm the session");
        }
    }

    // HELLO arms the heartbeat schedule for the connection that sent it.
    #[tokio::test]
    async fn hello_reschedules_heartbeats() {
        let (dave_tx, _dave_rx) = mpsc::unbounded_channel();
        let dispatcher = EventDispatcher::new();
        let (speak_tx, _speak_rx) = mpsc::unbounded_channel();
        let reannounce = SpeakingReannounce {
            ws_tx: speak_tx,
            speaking: Arc::new(AtomicBool::new(false)),
            ssrc: Arc::new(AtomicU32::new(0)),
        };
        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        let ping = Arc::new(AtomicU64::new(0));
        let mut last_seq: u64 = 0;
        let mut confirmed = false;
        let mut hb = interval_at(
            tokio::time::Instant::now() + Duration::from_secs(60),
            Duration::from_secs(60),
        );

        handle_inbound(
            Message::text(r#"{"op":8,"d":{"heartbeat_interval":5000}}"#),
            &dave_tx,
            &dispatcher,
            &reannounce,
            &state,
            &mut last_seq,
            &ping,
            None,
            &mut confirmed,
            &mut hb,
            &None,
        );

        assert_eq!(hb.period(), Duration::from_millis(5000));
    }
}
