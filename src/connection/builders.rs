use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

pub(super) fn identify_message(info: &SessionInfo) -> String {
    json!({
        "op": 0,
        "d": {
            "server_id": info.server_id.to_string(),
            "user_id": info.user_id.to_string(),
            "channel_id": info.channel_id.to_string(),
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
            "codecs": [{ "name": "opus", "payload_type": crate::rtp::PAYLOAD_TYPE_OPUS, "priority": 1000, "type": "audio" }],
            "data": { "address": discovered.ip, "port": discovered.port, "mode": mode },
            // The UDP address is also mirrored at the top level of the payload.
            "address": discovered.ip,
            "port": discovered.port,
            "mode": mode,
        }
    })
    .to_string()
}

/// Voice gateway v8 heartbeat: epoch-millis timestamp plus the last acknowledged sequence.
pub(super) fn heartbeat_message(seq_ack: u64) -> Message {
    Message::text(json!({ "op": 3, "d": { "t": now_millis(), "seq_ack": seq_ack } }).to_string())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The op-4 transport secret: a JSON byte array.
pub(super) fn session_secret_key(d: &Value) -> Vec<u8> {
    d["secret_key"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|n| n.as_u64().map(|x| x as u8))
                .collect()
        })
        .unwrap_or_default()
}

/// The op-4 DAVE protocol version (0 = DAVE disabled for the channel).
pub(super) fn session_dave_version(d: &Value) -> u16 {
    d["dave_protocol_version"].as_u64().unwrap_or(0) as u16
}

pub(super) fn resume_message(resume: &SessionInfo, seq_ack: u64) -> Message {
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

/// Outbound DAVE binary frame: `[op][payload]`. The 2-byte sequence prefix is inbound-only; we ack
/// with `seq_ack` in the heartbeat instead.
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

/// Op 12 `VIDEO`: advertise our audio stream; video and rtx stay zero for an audio-only bot.
pub(super) fn video_message(ssrc: u32) -> Message {
    Message::text(
        json!({ "op": 12, "d": { "audio_ssrc": ssrc, "video_ssrc": 0, "rtx_ssrc": 0 } })
            .to_string(),
    )
}

/// Op 16 `VOICE_BACKEND_VERSION`: ask the gateway for its backend versions right after READY.
pub(super) fn backend_version_message() -> Message {
    Message::text(json!({ "op": 16, "d": {} }).to_string())
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
