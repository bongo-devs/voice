use super::*;

pub(super) fn identify_message(info: &VoiceServerInfo) -> String {
    json!({
        "op": 0,
        "d": {
            "server_id": info.guild_id.to_string(),
            "user_id": info.user_id.to_string(),
            "session_id": info.session_id,
            "token": info.token,
            "max_dave_protocol_version": crate::dave::davey::DAVE_PROTOCOL_VERSION,
            // Discord forces video off for bots regardless of this flag.
            "video": true,
        }
    })
    .to_string()
}

pub(super) fn select_protocol_message(discovered: &DiscoveredAddress, mode: &str) -> String {
    json!({
        "op": 1,
        "d": {
            "protocol": "udp",
            "data": { "address": discovered.ip, "port": discovered.port, "mode": mode }
        }
    })
    .to_string()
}

pub(super) fn heartbeat_message(nonce: u64, seq_ack: u64) -> Message {
    // Voice gateway v8: heartbeat carries a nonce and the last acknowledged sequence number.
    Message::text(json!({ "op": 3, "d": { "t": nonce, "seq_ack": seq_ack } }).to_string())
}

pub(super) fn resume_message(resume: &ResumeInfo, seq_ack: u64) -> Message {
    Message::text(
        json!({
            "op": 7,
            "d": {
                "server_id": resume.server_id.to_string(),
                "session_id": resume.session_id,
                "token": resume.token,
                "video": true,
                "seq_ack": seq_ack,
            }
        })
        .to_string(),
    )
}

pub(super) fn transition_ready_message(transition_id: u64) -> Message {
    Message::text(json!({ "op": 23, "d": { "transition_id": transition_id } }).to_string())
}

/// Client→server DAVE binary frame: `[op][payload]` (the 2-byte sequence prefix is a
/// server→client field only; the client acks via `seq_ack` in the heartbeat).
pub(super) fn dave_binary(op: u8, payload: &[u8]) -> Message {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(op);
    buf.extend_from_slice(payload);
    Message::binary(buf)
}

pub(super) fn speaking_message(speaking: bool, ssrc: u32) -> Message {
    Message::text(
        json!({ "op": 5, "d": { "speaking": speaking as u8, "delay": 0, "ssrc": ssrc } })
            .to_string(),
    )
}

/// Op 15 `MEDIA_SINK_WANTS` with `any: 0`. There is no receive path here, so stop the SFU
/// forwarding other members' media that we would only drop.
pub(super) fn media_sink_wants_message() -> Message {
    Message::text(json!({ "op": 15, "d": { "any": 0 } }).to_string())
}

/// A normal (1000) close frame, sent on `disconnect`. The code retires the voice session
/// immediately instead of waiting for it to time out, which is what makes an instant rejoin work.
pub(super) fn close_message() -> Message {
    Message::Close(Some(CloseFrame {
        code: CloseCode::Normal,
        reason: Default::default(),
    }))
}
