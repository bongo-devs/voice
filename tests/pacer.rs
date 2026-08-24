//! Tests the 20 ms pacer: RTP framing, silence draining, and sequence/timestamp progression.

use bytes::Bytes;
use voice::rtp::RTP_HEADER_LEN;
use voice::{
    DaveEncryptor, FramePacer, PacerStatus, VecSink, SAMPLES_PER_FRAME, SILENCE_FRAME_COUNT,
};

#[tokio::test]
async fn paces_audio_then_silence_then_idle() {
    // A provider that yields three real frames, then nothing.
    let mut remaining = vec![
        Bytes::from_static(b"frame-c"),
        Bytes::from_static(b"frame-b"),
        Bytes::from_static(b"frame-a"),
    ];
    let provider = move || remaining.pop();

    let sink = VecSink::new();
    let dave = DaveEncryptor::new(1, 2).expect("create DAVE session");
    let mut pacer = FramePacer::new(provider, sink.clone(), dave, 0xDEAD_BEEF);

    let mut statuses = Vec::new();
    for _ in 0..(3 + SILENCE_FRAME_COUNT as usize + 2) {
        statuses.push(pacer.tick().await.unwrap());
    }

    // 3 audio frames, then SILENCE_FRAME_COUNT silence frames, then idle.
    assert_eq!(statuses[0], PacerStatus::Sent);
    assert_eq!(statuses[2], PacerStatus::Sent);
    assert_eq!(statuses[3], PacerStatus::Silence);
    assert_eq!(
        statuses[3 + SILENCE_FRAME_COUNT as usize - 1],
        PacerStatus::Silence
    );
    assert_eq!(
        statuses[3 + SILENCE_FRAME_COUNT as usize],
        PacerStatus::Idle
    );

    let packets = sink.packets();
    // 3 audio + 5 silence = 8 packets sent.
    assert_eq!(packets.len(), 3 + SILENCE_FRAME_COUNT as usize);

    // Every packet has the 12-byte RTP header.
    for p in &packets {
        assert!(p.len() > RTP_HEADER_LEN);
    }

    // Sequence numbers increment by 1, timestamps by 960.
    let seq0 = u16::from_be_bytes([packets[0][2], packets[0][3]]);
    let seq1 = u16::from_be_bytes([packets[1][2], packets[1][3]]);
    assert_eq!(seq1, seq0.wrapping_add(1));

    let ts0 = u32::from_be_bytes([packets[0][4], packets[0][5], packets[0][6], packets[0][7]]);
    let ts1 = u32::from_be_bytes([packets[1][4], packets[1][5], packets[1][6], packets[1][7]]);
    assert_eq!(ts1, ts0.wrapping_add(SAMPLES_PER_FRAME));

    // SSRC is preserved.
    let ssrc = u32::from_be_bytes([packets[0][8], packets[0][9], packets[0][10], packets[0][11]]);
    assert_eq!(ssrc, 0xDEAD_BEEF);

    // First audio packet carries the original payload after the header.
    assert_eq!(&packets[0][RTP_HEADER_LEN..], b"frame-a");
}
