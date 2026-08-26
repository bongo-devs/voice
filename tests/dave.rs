//! Verifies the davey-backed DAVE encryptor integrates with the pacer.

use bytes::Bytes;
use voice::dave::davey::SessionStatus;
use voice::{DaveEncryptor, FramePacer, PacerStatus, VecSink};

#[test]
fn dave_encryptor_passes_through_until_group_active() {
    let mut enc = DaveEncryptor::new(123_456_789, 987_654_321).expect("create DAVE session");
    assert_eq!(enc.status(), SessionStatus::INACTIVE);
    assert!(!enc.is_ready());

    let frame = b"an-opus-frame";
    let out = enc
        .encrypt(frame)
        .expect("passthrough before group is active");
    assert_eq!(&out[..], frame);
}

#[tokio::test]
async fn pacer_runs_with_dave_encryptor() {
    let mut frames = vec![Bytes::from_static(b"b"), Bytes::from_static(b"a")];
    let provider = move || frames.pop();
    let sink = VecSink::new();
    let enc = DaveEncryptor::new(1, 2).expect("create DAVE session");

    let mut pacer = FramePacer::new(provider, sink.clone(), enc, 0x1234);
    assert_eq!(pacer.tick().await.unwrap(), PacerStatus::Sent);
    assert_eq!(pacer.tick().await.unwrap(), PacerStatus::Sent);

    let packets = sink.packets();
    assert_eq!(packets.len(), 2);
    // 12-byte RTP header, then the passed-through payload.
    assert_eq!(&packets[0][12..], b"a");
}
