//! Tests for channel envelope packing/unpacking.

use reticulum_protocol::channel::Envelope;
use reticulum_test_vectors::channels;

// ---------------------------------------------------------------------------
// Test vector tests
// ---------------------------------------------------------------------------

#[test]
fn envelope_pack_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.envelope_vectors {
        let envelope = Envelope {
            msg_type: v.msgtype as u16,
            sequence: v.sequence as u16,
            payload: hex::decode(&v.data_hex).unwrap(),
        };
        let packed = envelope.pack();
        let expected = hex::decode(&v.packed_hex).unwrap();
        assert_eq!(
            packed, expected,
            "pack failed for vector {}: {}",
            v.index, v.description
        );
    }
}

#[test]
fn envelope_unpack_all_vectors() {
    let vectors = channels::load();
    for v in &vectors.envelope_vectors {
        let packed = hex::decode(&v.packed_hex).unwrap();
        let envelope = Envelope::unpack(&packed).unwrap_or_else(|e| {
            panic!(
                "unpack failed for vector {}: {} — {e}",
                v.index, v.description
            )
        });
        assert_eq!(
            envelope.msg_type, v.decoded_msgtype as u16,
            "msg_type mismatch for vector {}: {}",
            v.index, v.description
        );
        assert_eq!(
            envelope.sequence, v.decoded_sequence as u16,
            "sequence mismatch for vector {}: {}",
            v.index, v.description
        );
        let expected_payload = hex::decode(&v.decoded_data_hex).unwrap();
        assert_eq!(
            envelope.payload, expected_payload,
            "payload mismatch for vector {}: {}",
            v.index, v.description
        );
        assert_eq!(
            envelope.payload.len(),
            v.decoded_length as usize,
            "decoded length mismatch for vector {}: {}",
            v.index,
            v.description
        );
    }
}

#[test]
fn envelope_pack_length_matches_vector() {
    let vectors = channels::load();
    for v in &vectors.envelope_vectors {
        let envelope = Envelope {
            msg_type: v.msgtype as u16,
            sequence: v.sequence as u16,
            payload: hex::decode(&v.data_hex).unwrap(),
        };
        let packed = envelope.pack();
        assert_eq!(
            packed.len(),
            v.packed_length as usize,
            "packed length mismatch for vector {}: {}",
            v.index,
            v.description
        );
    }
}

#[test]
fn envelope_header_matches_vector() {
    let vectors = channels::load();
    for v in &vectors.envelope_vectors {
        let envelope = Envelope {
            msg_type: v.msgtype as u16,
            sequence: v.sequence as u16,
            payload: hex::decode(&v.data_hex).unwrap(),
        };
        let packed = envelope.pack();
        let header = hex::encode(&packed[..Envelope::OVERHEAD]);
        assert_eq!(
            header, v.header_hex,
            "header mismatch for vector {}: {}",
            v.index, v.description
        );
    }
}

// ---------------------------------------------------------------------------
// Error case tests
// ---------------------------------------------------------------------------

#[test]
fn envelope_unpack_too_short() {
    // Anything shorter than 6 bytes must fail
    for len in 0..6 {
        let data = vec![0u8; len];
        assert!(
            Envelope::unpack(&data).is_err(),
            "unpack should reject {len}-byte input"
        );
    }
}

#[test]
fn envelope_unpack_length_mismatch() {
    // Header says 10 bytes payload, but only 5 bytes follow
    let mut data = vec![0u8; 6 + 5];
    data[4] = 0;
    data[5] = 10; // length field = 10
    assert!(Envelope::unpack(&data).is_err());
}

// ---------------------------------------------------------------------------
// Property tests (proptest)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip(msg_type: u16, sequence: u16, payload in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let envelope = Envelope { msg_type, sequence, payload };
            let packed = envelope.pack();
            let unpacked = Envelope::unpack(&packed).unwrap();
            prop_assert_eq!(&unpacked, &envelope);
        }

        #[test]
        fn pack_length(msg_type: u16, sequence: u16, payload in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let envelope = Envelope { msg_type, sequence, payload: payload.clone() };
            let packed = envelope.pack();
            prop_assert_eq!(packed.len(), Envelope::OVERHEAD + payload.len());
        }

        #[test]
        fn full_u16_range(msg_type: u16, sequence: u16) {
            let envelope = Envelope { msg_type, sequence, payload: vec![] };
            let packed = envelope.pack();
            let unpacked = Envelope::unpack(&packed).unwrap();
            prop_assert_eq!(unpacked.msg_type, msg_type);
            prop_assert_eq!(unpacked.sequence, sequence);
        }
    }
}
