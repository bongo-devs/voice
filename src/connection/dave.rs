use super::builders::{dave_binary, transition_ready_message};
use super::*;
use crate::dave::davey::errors::ProcessCommitError;

/// Apply one DAVE event to the session and emit any required gateway response.
pub(super) fn handle_dave_event(
    dave: &mut DaveEncryptor,
    pending: &mut HashMap<u64, u16>,
    roster: &mut HashSet<u64>,
    event: DaveEvent,
    ws_tx: &mpsc::UnboundedSender<Message>,
) {
    match event {
        DaveEvent::Binary { op, payload } => {
            handle_dave_binary(dave, roster, op, &payload, ws_tx);
        }
        // The roster of users the gateway has announced, which MLS Add proposals are validated
        // against.
        DaveEvent::UsersConnected { user_ids } => roster.extend(user_ids),
        DaveEvent::UserDisconnected { user_id } => {
            roster.remove(&user_id);
        }
        DaveEvent::PrepareTransition {
            protocol_version,
            transition_id,
        } => {
            pending.insert(transition_id, protocol_version);
            // A downgrade to v0 (DAVE disabled): allow plaintext during the grace period.
            if protocol_version == 0 {
                dave.set_passthrough(true);
            }
            // Transition 0 is the initial handshake and is not acknowledged.
            if transition_id != 0 {
                let _ = ws_tx.send(transition_ready_message(transition_id));
            }
        }
        DaveEvent::ExecuteTransition { transition_id } => {
            // On a v0 downgrade tear the MLS group down (`reset`); on an upgrade the new epoch's
            // ratchet was already installed by `process_commit`, so just leave passthrough to
            // resume encrypting once the transition completes.
            if let Some(protocol_version) = pending.remove(&transition_id) {
                if protocol_version == 0 {
                    dave.reset();
                } else {
                    dave.set_passthrough(false);
                }
            }
        }
        DaveEvent::PrepareEpoch {
            protocol_version,
            epoch,
        } => {
            tracing::debug!(protocol_version, epoch, "DAVE prepare epoch");
            // Epoch 1 means Discord is re-keying into a *fresh* MLS group (e.g. a member
            // left/rejoined). Re-initialise the session first so the old group is torn down and the
            // new group's proposals/welcome are accepted — otherwise davey rejects them with `Wrong
            // Epoch` / `AlreadyInGroup` and every frame fails to encrypt → silence. Then send our
            // key package so the gateway can add us to the new group.
            if epoch == 1 {
                if let Err(error) = dave.reinit() {
                    tracing::warn!(%error, "DAVE: failed to reinit session for new epoch");
                }
                send_key_package(dave, ws_tx);
            }
        }
    }
}

/// Create a fresh MLS key package and queue it as op 26 (`dave_mls_key_package`). Sent on
/// `SESSION_DESCRIPTION` when DAVE is enabled, and again on an op-24 prepare-epoch for a new group;
/// davey builds a fresh, single-use package on each call.
pub(super) fn send_key_package(dave: &mut DaveEncryptor, ws_tx: &mpsc::UnboundedSender<Message>) {
    match dave.session_mut().create_key_package() {
        Ok(key_package) => {
            tracing::debug!("DAVE: sending key package");
            let _ = ws_tx.send(dave_binary(OP_DAVE_MLS_KEY_PACKAGE, &key_package));
        }
        Err(error) => tracing::warn!(%error, "DAVE: failed to create key package"),
    }
}

/// Apply one inbound binary MLS op to the session, sending any gateway responses via `ws_tx`.
///
/// A commit/welcome that davey merely *ignores* (it predates our group state) is logged and dropped.
/// A genuine failure sends a JSON `invalid_commit_welcome` (op 31) carrying the transition id and
/// re-sends our key package so the gateway removes and re-adds us; for a bad *commit* we also
/// re-initialise the session first, because davey requires a reset before it will accept a fresh
/// welcome. A bad *welcome* is not reset.
///
/// Applying a commit or welcome successfully is acknowledged with op 23 `ready_for_transition`.
///
/// Each op's payload is the bytes *after* the 2-byte sequence number and 1-byte opcode; the extra
/// per-op framing in front of the raw MLS bytes (the op-27 operation-type byte, the op-29/30
/// transition id) must be stripped here before handing the MLS bytes to `davey` — feeding it the
/// framing bytes makes TLS deserialization fail and silently stalls the whole handshake.
pub(super) fn handle_dave_binary(
    dave: &mut DaveEncryptor,
    roster: &HashSet<u64>,
    op: u8,
    payload: &[u8],
    ws_tx: &mpsc::UnboundedSender<Message>,
) {
    match op {
        OP_DAVE_MLS_EXTERNAL_SENDER => {
            // Only the external sender is set here — the key package is sent earlier (on
            // `SESSION_DESCRIPTION`) and on an op-24 prepare-epoch, not in response to op 25.
            match dave.session_mut().set_external_sender(payload) {
                Ok(()) => tracing::debug!("DAVE: external sender set"),
                Err(error) => tracing::warn!(%error, "DAVE: failed to set external sender"),
            }
        }
        OP_DAVE_MLS_PROPOSALS => {
            let Some((operation_type, proposals)) = split_proposals(payload) else {
                return;
            };
            // davey needs the recognized-user roster (op 11/13 plus our own id) to run its
            // `UnexpectedUser` check. Passing `None` skips it, letting any id the gateway never
            // announced be added to the group.
            let expected = expected_user_ids(roster, dave.session().user_id());
            match dave
                .session_mut()
                .process_proposals(operation_type, proposals, Some(&expected))
            {
                Ok(Some(commit_welcome)) => {
                    let mut out = commit_welcome.commit;
                    if let Some(welcome) = commit_welcome.welcome {
                        out.extend_from_slice(&welcome);
                    }
                    tracing::debug!(
                        ?operation_type,
                        "DAVE: proposals processed, sending commit/welcome"
                    );
                    let _ = ws_tx.send(dave_binary(OP_DAVE_MLS_COMMIT_WELCOME, &out));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "DAVE: failed to process proposals");
                }
            }
        }
        OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION => {
            let Some((transition_id, commit)) = strip_transition_id(payload) else {
                return;
            };
            match dave.session_mut().process_commit(commit) {
                Ok(()) => {
                    tracing::debug!(transition_id, "DAVE: commit processed");
                    send_transition_ready(transition_id, ws_tx);
                }
                // davey refuses a commit that arrives while we are still being onboarded
                // (`PendingGroup` — our pending group exists but the welcome hasn't landed) or
                // before any group exists (`NoGroup`). Those are routine broadcast ops, not
                // failures. Treating them as invalid aborts our own join and can loop (op 31 →
                // fresh key package → PENDING again), which keeps `is_ready()` false and leaves us
                // emitting plaintext into an active E2EE group — silence for every peer.
                Err(error @ (ProcessCommitError::NoGroup | ProcessCommitError::PendingGroup)) => {
                    tracing::debug!(transition_id, %error, "DAVE: commit ignored");
                }
                Err(error) => {
                    tracing::warn!(transition_id, %error, "DAVE: invalid commit, requesting re-add");
                    recover_from_invalid(dave, transition_id, ws_tx);
                }
            }
        }
        OP_DAVE_MLS_WELCOME => {
            let Some((transition_id, welcome)) = strip_transition_id(payload) else {
                return;
            };
            match dave.session_mut().process_welcome(welcome) {
                Ok(()) => {
                    tracing::debug!(transition_id, "DAVE: welcome processed, group active");
                    send_transition_ready(transition_id, ws_tx);
                }
                // The failure path is op 31 plus a fresh key package and nothing else — no reinit.
                // A duplicate welcome fails with `AlreadyInGroup`, and resetting there would tear
                // down the group we are already encrypting with.
                Err(error) => {
                    tracing::warn!(transition_id, %error, "DAVE: invalid welcome, requesting re-add");
                    let _ = ws_tx.send(invalid_commit_welcome_message(transition_id));
                    send_key_package(dave, ws_tx);
                }
            }
        }
        _ => {}
    }
}

/// Once a commit or welcome has been applied, tell the gateway we are ready so it can complete the
/// transition for the whole channel — without this the transition stalls for every peer. Transition
/// 0 is the initial handshake and is never acked.
fn send_transition_ready(transition_id: u16, ws_tx: &mpsc::UnboundedSender<Message>) {
    if transition_id != 0 {
        let _ = ws_tx.send(transition_ready_message(transition_id as u64));
    }
}

/// Recover from a bad *commit*: tell the gateway our commit was invalid (op 31), re-initialise the
/// session, and re-send our key package so we are removed and re-added to the group. Without the
/// reinit, davey would keep rejecting the next welcome with `AlreadyInGroup`. (A bad *welcome* skips
/// the reinit — see the op-30 arm.)
pub(super) fn recover_from_invalid(
    dave: &mut DaveEncryptor,
    transition_id: u16,
    ws_tx: &mpsc::UnboundedSender<Message>,
) {
    let _ = ws_tx.send(invalid_commit_welcome_message(transition_id));
    if let Err(error) = dave.reinit() {
        tracing::warn!(%error, "DAVE: failed to reinit after invalid commit/welcome");
    }
    send_key_package(dave, ws_tx);
}

/// The recognized-user roster plus our own id (we are always a legitimate member of our own group).
fn expected_user_ids(roster: &HashSet<u64>, self_user_id: u64) -> Vec<u64> {
    let mut ids = Vec::with_capacity(roster.len() + 1);
    ids.extend(roster.iter().copied());
    ids.push(self_user_id);
    ids
}

/// Split an op-27 `dave_mls_proposals` payload into its operation type and the raw MLS proposals
/// bytes. Wire layout (after `[seq][op]`): `[operation_type: u8][proposals…]`. Returns `None` for
/// an empty payload or an unknown operation type.
pub(super) fn split_proposals(payload: &[u8]) -> Option<(ProposalsOperationType, &[u8])> {
    let (&optype, proposals) = payload.split_first()?;
    let operation_type = match optype {
        0 => ProposalsOperationType::APPEND,
        1 => ProposalsOperationType::REVOKE,
        other => {
            tracing::warn!(
                operation_type = other,
                "DAVE: unknown proposals operation type"
            );
            return None;
        }
    };
    Some((operation_type, proposals))
}

/// Strip the 2-byte big-endian `transition_id` that prefixes an op-29 (`announce_commit_transition`)
/// or op-30 (`welcome`) payload, returning it alongside the trailing MLS commit/welcome bytes.
/// Wire layout (after `[seq][op]`): `[transition_id: u16][mls…]`.
pub(super) fn strip_transition_id(payload: &[u8]) -> Option<(u16, &[u8])> {
    let (id_bytes, mls) = payload.split_at_checked(2)?;
    Some((u16::from_be_bytes([id_bytes[0], id_bytes[1]]), mls))
}

/// Client→server op 31 `dave_mls_invalid_commit_welcome` — a JSON message (not binary) carrying the
/// transition id whose commit/welcome we could not process, asking the gateway to re-add us.
pub(super) fn invalid_commit_welcome_message(transition_id: u16) -> Message {
    Message::text(
        json!({
            "op": OP_DAVE_MLS_INVALID_COMMIT_WELCOME,
            "d": { "transition_id": transition_id }
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_tracks_gateway_users_and_always_expects_self() {
        // Op 11 adds users, op 13 removes one, and the expected-id list appends our own id. Passing
        // that to `process_proposals` is what makes davey reject an Add for a user the gateway never
        // announced.
        let mut dave = DaveEncryptor::new(7, 9).expect("create session");
        let mut pending = HashMap::new();
        let mut roster = HashSet::new();
        let (ws_tx, _ws_rx) = mpsc::unbounded_channel();

        for event in [
            DaveEvent::UsersConnected {
                user_ids: vec![1, 2],
            },
            DaveEvent::UserDisconnected { user_id: 1 },
        ] {
            handle_dave_event(&mut dave, &mut pending, &mut roster, event, &ws_tx);
        }
        assert_eq!(roster, HashSet::from([2]));

        let mut expected = expected_user_ids(&roster, dave.session().user_id());
        expected.sort_unstable();
        assert_eq!(expected, vec![2, 7], "roster plus self");
    }
}
