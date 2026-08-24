use super::builders::speaking_message;
use super::dave::handle_dave_event;
use super::*;

/// The 20 ms send task: paces audio frames through the [`FramePacer`] (DAVE → transport → RTP →
/// UDP) and applies DAVE MLS messages between ticks.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_loop<P>(
    provider: P,
    udp: VoiceUdp,
    dave: DaveEncryptor,
    transport: Box<dyn crate::transport::TransportCipher>,
    ssrc: u32,
    ws_tx: mpsc::UnboundedSender<Message>,
    mut dave_rx: mpsc::UnboundedReceiver<DaveEvent>,
    dispatcher: EventDispatcher,
    speaking_flag: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
) where
    P: OpusFrameProvider,
{
    let speaking_tx = ws_tx.clone();
    let mut pacer = FramePacer::with_transport(provider, udp, dave, transport, ssrc);
    pacer.on_speaking(move |speaking| {
        // Keep the shared flag in sync so the gateway task can re-announce it on op 11/12.
        speaking_flag.store(speaking, Ordering::Relaxed);
        let _ = speaking_tx.send(speaking_message(speaking, ssrc));
    });

    // Pending protocol-version transitions, keyed by transition id (set on prepare, applied on
    // execute).
    let mut pending: HashMap<u64, u16> = HashMap::new();
    // Users the gateway announced via op 11/13, used to validate MLS Add proposals.
    let mut roster: HashSet<u64> = HashSet::new();
    let mut dave_open = true;
    let mut was_ready = pacer.dave_mut().is_ready();

    // Absolute per-slot deadlines, so a late tick is caught up instead of letting the lateness
    // accumulate.
    let mut clock = FrameClock::new();

    // A few transient UDP send failures shouldn't tear down the connection; drop the frame and keep
    // going. Only give up after sustained failure (~1 s) so a genuinely dead socket still lets the
    // gateway drive a reconnect, rather than spinning forever.
    let mut consecutive_send_errors: u32 = 0;
    const MAX_CONSECUTIVE_SEND_ERRORS: u32 = 50;

    loop {
        // Stop once the gateway supervisor declares the connection dead (a fatal, non-resumable
        // close). UDP sends don't error on a dead session, so without this the pacer would keep
        // ticking and blindly sending RTP forever, leaking a 50 fps task until the connection is
        // dropped. (`disconnect`/`Drop` abort the task directly; this covers the gateway-fatal path
        // where neither runs.)
        if ConnectionState::from_u8(state.load(Ordering::SeqCst)) == ConnectionState::Closed {
            break;
        }
        tokio::select! {
            _ = clock.wait() => {
                match pacer.tick().await {
                    Ok(_) => consecutive_send_errors = 0,
                    Err(error) => {
                        consecutive_send_errors += 1;
                        tracing::warn!(
                            %error,
                            consecutive = consecutive_send_errors,
                            "voice: frame send failed; dropping frame"
                        );
                        if consecutive_send_errors >= MAX_CONSECUTIVE_SEND_ERRORS {
                            tracing::warn!(
                                "voice: too many consecutive send failures, stopping send loop"
                            );
                            // The socket is gone for good, so this connection is dead even though
                            // the gateway WebSocket still reads fine. Mark it closed so the caller
                            // can rebuild it, report 4900 so the close is visible, and close the
                            // gateway so the supervisor task stops too. Storing `Closed` first is
                            // what keeps the supervisor from resuming or double-reporting.
                            state.store(ConnectionState::Closed as u8, Ordering::SeqCst);
                            dispatcher.dispatch(VoiceEvent::GatewayClosed {
                                code: 4900,
                                reason: "udp send failed".into(),
                                by_remote: false,
                            });
                            let _ = ws_tx.send(close_message());
                            break;
                        }
                    }
                }
            }
            event = dave_rx.recv(), if dave_open => {
                match event {
                    Some(event) => {
                        handle_dave_event(
                            pacer.dave_mut(),
                            &mut pending,
                            &mut roster,
                            event,
                            &ws_tx,
                        );
                        // The MLS group flipping to active means end-to-end encryption is now in
                        // effect — announce it once, with the human-verifiable privacy code.
                        let ready = pacer.dave_mut().is_ready();
                        if ready && !was_ready {
                            let privacy_code =
                                pacer.dave_mut().voice_privacy_code().map(str::to_owned);
                            tracing::info!(
                                privacy_code = privacy_code.as_deref(),
                                "voice: DAVE end-to-end encryption active"
                            );
                            dispatcher.dispatch(VoiceEvent::DaveSessionReady { privacy_code });
                        }
                        was_ready = ready;
                    }
                    None => dave_open = false,
                }
            }
        }
    }
}
