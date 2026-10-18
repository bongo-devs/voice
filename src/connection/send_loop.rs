use super::builders::speaking_message;
use super::dave::{handle_dave_event, send_key_package};
use super::*;

/// The 20 ms send task, pacing frames through the [`FramePacer`] and applying DAVE MLS messages.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_loop<P>(
    provider: P,
    udp: VoiceUdp,
    dave: DaveEncryptor,
    transport: Box<dyn crate::transport::TransportCipher>,
    ssrc: Arc<AtomicU32>,
    ws_tx: mpsc::UnboundedSender<Message>,
    mut dave_rx: mpsc::UnboundedReceiver<DaveEvent>,
    dispatcher: EventDispatcher,
    speaking_flag: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
) where
    P: OpusFrameProvider,
{
    let speaking_tx = ws_tx.clone();
    let speaking_ssrc = ssrc.clone();
    let speaking_sync = speaking_flag.clone();
    let mut pacer =
        FramePacer::with_transport(provider, udp, dave, transport, ssrc.load(Ordering::Relaxed));
    pacer.on_speaking(move |speaking| {
        // Keep the shared flag in sync; the gateway task re-announces from it on op 4/op 12.
        speaking_sync.store(speaking, Ordering::Relaxed);
        // Only the start of a burst is announced; an explicit stop is off by default.
        if speaking {
            let ssrc = speaking_ssrc.load(Ordering::Relaxed);
            let _ = speaking_tx.send(speaking_message(true, ssrc));
        }
    });

    // Pending protocol-version transitions, keyed by transition id (set on prepare, applied on
    // execute).
    let mut pending: HashMap<u64, u16> = HashMap::new();
    // Users the gateway announced via op 11/13, used to validate MLS Add proposals.
    let mut roster: HashSet<u64> = HashSet::new();
    let mut dave_open = true;
    let mut was_ready = pacer.dave_mut().is_ready();

    // Absolute per-slot deadlines, so a late tick is caught up instead of accumulating.
    let mut clock = FrameClock::new();

    // Failed datagrams are dropped frames, not a dead session: only the gateway controls that.
    let mut consecutive_send_errors: u32 = 0;

    loop {
        // UDP sends keep succeeding after a fatal gateway close, so without this the pacer would
        // tick and send RTP forever, leaking a 50 fps task.
        if ConnectionState::from_u8(state.load(Ordering::SeqCst)) == ConnectionState::Closed {
            break;
        }
        tokio::select! {
            _ = clock.wait() => {
                match pacer.tick().await {
                    Ok(_) => consecutive_send_errors = 0,
                    Err(error) => {
                        consecutive_send_errors += 1;
                        // One warn per streak, then keep the per-frame noise at debug level.
                        if consecutive_send_errors == 1 {
                            tracing::warn!(%error, "voice: frame send failed; dropping frame");
                        } else {
                            tracing::debug!(
                                %error,
                                consecutive = consecutive_send_errors,
                                "voice: frame send failed; dropping frame"
                            );
                        }
                    }
                }
            }
            event = dave_rx.recv(), if dave_open => {
                match event {
                    // A fresh session replaces the whole UDP leg: new socket, cipher, and SSRC.
                    Some(DaveEvent::FreshSession {
                        udp,
                        transport,
                        ssrc,
                        dave_protocol_version,
                    }) => {
                        pacer.swap_link(udp, transport, ssrc);
                        pending.clear();
                        if dave_protocol_version > 0 {
                            if let Err(error) = pacer.dave_mut().reinit_version(dave_protocol_version) {
                                tracing::warn!(%error, "DAVE: failed to reinit for the fresh session");
                            }
                            send_key_package(pacer.dave_mut(), &ws_tx);
                        } else {
                            pacer.dave_mut().reset();
                        }
                        was_ready = pacer.dave_mut().is_ready();
                        // The fresh link starts silent: reflect that in the shared flag.
                        speaking_flag.store(false, Ordering::Relaxed);
                    }
                    Some(event) => {
                        handle_dave_event(
                            pacer.dave_mut(),
                            &mut pending,
                            &mut roster,
                            event,
                            &ws_tx,
                        );
                        // The group flipping to active means end-to-end encryption is on, so
                        // announce it once with the privacy code.
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
