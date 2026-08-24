use super::builders::{heartbeat_message, resume_message};
use super::*;

/// Gateway supervisor: owns the WebSocket, heartbeats, dispatches inbound ops, and resumes on a
/// dropped connection while the send task (UDP/DAVE) keeps running.
#[allow(clippy::too_many_arguments)]
pub(super) async fn gateway_loop(
    resume: ResumeInfo,
    mut sink: WsSink,
    mut stream: WsSource,
    mut ws_rx: mpsc::UnboundedReceiver<Message>,
    dave_tx: mpsc::UnboundedSender<DaveEvent>,
    heartbeat_interval_ms: f64,
    mut last_seq: u64,
    state: Arc<AtomicU8>,
    ping: Arc<AtomicU64>,
    dispatcher: EventDispatcher,
    reannounce: SpeakingReannounce,
) {
    let mut hb = interval(Duration::from_millis(heartbeat_interval_ms.max(1.0) as u64));
    hb.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut nonce: u64 = 0;

    loop {
        let outcome = pump(
            &mut sink,
            &mut stream,
            &mut ws_rx,
            &dave_tx,
            &dispatcher,
            &reannounce,
            &mut hb,
            &mut nonce,
            &mut last_seq,
            &ping,
            &state,
        )
        .await;

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
                // We asked for this close: `disconnect` (and the send loop giving up) store `Closed`
                // before the close frame goes out. Neither resume it nor report it as a gateway
                // failure — a local stop is not a gateway close.
                if ConnectionState::from_u8(state.load(Ordering::SeqCst)) == ConnectionState::Closed
                {
                    tracing::debug!(code = code.unwrap_or(0), "voice: gateway closed locally");
                    break;
                }
                let mut recovered = false;
                if is_resumable(code) {
                    tracing::warn!(
                        code = code.unwrap_or(0),
                        "voice: gateway dropped, attempting resume"
                    );
                    state.store(ConnectionState::Reconnecting as u8, Ordering::SeqCst);
                    // Best-effort resume: reconnect and send op 7 with the last seen sequence.
                    // Exponential backoff with jitter — every connection on a host drops together
                    // when Discord cycles a voice server, and a fixed schedule would have them all
                    // reconnect in lockstep.
                    for attempt in 0..5u32 {
                        sleep(backoff_delay(attempt)).await;
                        if let Ok((new_sink, new_stream)) = reconnect(&resume.url).await {
                            sink = new_sink;
                            stream = new_stream;
                            if sink.send(resume_message(&resume, last_seq)).await.is_ok() {
                                recovered = true;
                                break;
                            }
                        }
                    }
                }
                if recovered {
                    tracing::info!("voice: gateway session resumed");
                    state.store(ConnectionState::Connected as u8, Ordering::SeqCst);
                } else {
                    tracing::warn!(
                        code = code.unwrap_or(0),
                        reason = %reason,
                        by_remote,
                        "voice: gateway closed"
                    );
                    state.store(ConnectionState::Closed as u8, Ordering::SeqCst);
                    dispatcher.dispatch(VoiceEvent::GatewayClosed {
                        code: code.unwrap_or(0),
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

/// Resume backoff: `500 ms * 2^attempt` capped at 8 s, plus up to 500 ms of jitter.
///
/// The jitter comes from the wall clock's sub-millisecond digits rather than pulling in `rand` — a
/// reconnect delay does not need a real PRNG, only de-synchronised connections.
pub(super) fn backoff_delay(attempt: u32) -> Duration {
    let base = Duration::from_millis(500 << attempt.min(4));
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| (since.subsec_nanos() % 500_000) as u64)
        .unwrap_or(0);
    base + Duration::from_micros(jitter)
}

/// Outcome of one [`pump`] over a single WebSocket lifetime.
enum PumpOutcome {
    /// The outbound channel closed (the connection was disconnected/dropped) — stop entirely.
    Stop,
    /// The WebSocket closed or errored. `code` is the close code if the peer sent a close frame
    /// (`None` for an abnormal drop or local I/O failure); the supervisor decides
    /// resume-vs-fatal from it via [`is_resumable`].
    Closed {
        /// The close code, if a close frame was received.
        code: Option<u16>,
        /// The close reason text (empty if none).
        reason: String,
        /// Whether the remote (Discord) initiated the close.
        by_remote: bool,
    },
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
    nonce: &mut u64,
    last_seq: &mut u64,
    ping: &Arc<AtomicU64>,
    state: &Arc<AtomicU8>,
) -> PumpOutcome {
    // When the last heartbeat was sent, used to compute the round-trip on the matching ACK (op 6).
    let mut last_heartbeat: Option<Instant> = None;
    // When we last saw an op 6. A voice gateway that stops acking is dead even though the TCP
    // connection reads fine; without this watchdog a zombie session silently swallows every frame
    // and nothing ever reconnects.
    let mut last_ack = Instant::now();
    let ack_timeout = hb.period() * MISSED_ACKS_BEFORE_DEAD;
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
                if last_ack.elapsed() > ack_timeout {
                    tracing::warn!(
                        elapsed_ms = last_ack.elapsed().as_millis(),
                        "voice: no heartbeat ack, treating the gateway as dead"
                    );
                    // `code: None` is resumable, so the supervisor reconnects and sends op 7.
                    return PumpOutcome::Closed {
                        code: None,
                        reason: "heartbeat ack timeout".into(),
                        by_remote: false,
                    };
                }
                *nonce = nonce.wrapping_add(1);
                if sink
                    .send(heartbeat_message(*nonce, *last_seq))
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
                Some(Ok(message)) => handle_inbound(
                    message,
                    dave_tx,
                    dispatcher,
                    reannounce,
                    state,
                    last_seq,
                    ping,
                    last_heartbeat,
                    &mut last_ack,
                ),
                Some(Err(error)) => {
                    dispatcher.dispatch(VoiceEvent::GatewayError {
                        message: error.to_string(),
                    });
                    return PumpOutcome::Closed {
                        code: None,
                        reason: "connection error".into(),
                        by_remote: false,
                    };
                }
                None => {
                    return PumpOutcome::Closed {
                        code: None,
                        reason: "connection closed".into(),
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

/// Track the server sequence and forward DAVE ops; ignore keep-alive / informational ops.
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
    last_ack: &mut Instant,
) {
    match message {
        // Binary header: seq (2, BE) + op (1) + MLS payload.
        Message::Binary(bytes) => {
            if bytes.len() >= 2 {
                *last_seq = (*last_seq).max(u16::from_be_bytes([bytes[0], bytes[1]]) as u64);
            }
            forward_dave_binary(&bytes, dave_tx);
        }
        Message::Text(text) => {
            let Ok(value) = serde_json::from_str::<Value>(text.as_str()) else {
                return;
            };
            if let Some(s) = value["seq"].as_u64() {
                *last_seq = (*last_seq).max(s);
            }
            let d = &value["d"];
            let Some(op) = value["op"].as_u64() else {
                return;
            };
            forward_dave_json(op, d, dave_tx);
            match op {
                // Op 6 `HEARTBEAT_ACK`: record the round-trip since the last heartbeat as the ping.
                6 => {
                    *last_ack = Instant::now();
                    if let Some(sent) = last_heartbeat {
                        ping.store(sent.elapsed().as_millis() as u64, Ordering::Relaxed);
                    }
                }
                // Op 9 `RESUMED`: the gateway accepted our op 7, so the session really is live again
                // (the supervisor stores `Connected` optimistically when the resume is *sent*).
                9 => {
                    tracing::info!("voice: gateway session resumed (RESUMED)");
                    state.store(ConnectionState::Connected as u8, Ordering::SeqCst);
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
                    // A client joined: re-announce speaking so it maps our SSRC and hears us.
                    reannounce.announce_if_speaking();
                }
                // Op 12 `VIDEO`: a single user's stream SSRCs changed (carries `user_id` +
                // `audio_ssrc`).
                12 => {
                    if let Some(user_id) = d["user_id"].as_str() {
                        dispatcher.dispatch(VoiceEvent::UserConnected {
                            user_id: user_id.to_string(),
                            audio_ssrc: d["audio_ssrc"].as_u64().unwrap_or(0) as u32,
                        });
                    }
                    // A client joined: re-announce speaking so it maps our SSRC and hears us.
                    reannounce.announce_if_speaking();
                }
                // Op 13 `CLIENT_DISCONNECT`.
                13 => {
                    if let Some(user_id) = d["user_id"].as_str() {
                        dispatcher.dispatch(VoiceEvent::UserDisconnected {
                            user_id: user_id.to_string(),
                        });
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}

/// Forward a server→client binary MLS op to the send task, which owns the DAVE session. Frame layout
/// is `[seq: u16 BE][op: u8][mls…]`.
///
/// Shared with the handshake in [`VoiceConnection::connect_with_dispatcher`]: Discord can start the
/// DAVE handshake before `SESSION_DESCRIPTION`, and dropping op 25 in that window is unrecoverable
/// (every later welcome then fails with `NoExternalSender`, and `reinit` cannot conjure one). The
/// receiver is unbounded, so ops that arrive before the send task exists simply queue.
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
    let (ws, _response) = connect_async(url).await?;
    Ok(ws.split())
}
