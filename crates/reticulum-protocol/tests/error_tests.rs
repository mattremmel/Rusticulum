//! Tests for protocol error types.

use reticulum_core::error::{IdentityError, PacketError};
use reticulum_crypto::CryptoError;
use reticulum_protocol::error::{
    BufferError, ChannelError, LinkError, RequestError, ResourceError,
};

#[test]
fn link_error_display_request_data_too_short() {
    let err = LinkError::RequestDataTooShort;
    assert_eq!(err.to_string(), "request data too short");
}

#[test]
fn link_error_display_request_data_conversion() {
    let err = LinkError::RequestDataConversion;
    assert_eq!(err.to_string(), "request data conversion failed");
}

#[test]
fn link_error_display_invalid_rtt_format() {
    let err = LinkError::InvalidRttFormat;
    assert_eq!(err.to_string(), "invalid RTT format");
}

#[test]
fn link_error_display_invalid_proof() {
    let err = LinkError::InvalidProof;
    assert_eq!(err.to_string(), "invalid link proof");
}

#[test]
fn link_error_display_invalid_state() {
    let err = LinkError::InvalidState {
        expected: "ACTIVE",
        actual: "PENDING",
    };
    assert_eq!(
        err.to_string(),
        "invalid state: expected ACTIVE, got PENDING"
    );
}

#[test]
fn link_error_display_unsupported_mode() {
    let err = LinkError::UnsupportedMode(42);
    assert_eq!(err.to_string(), "unsupported link mode: 42");
}

#[test]
fn link_error_from_crypto_error() {
    let crypto_err = CryptoError::DecryptionFailed;
    let link_err: LinkError = crypto_err.into();
    assert!(matches!(link_err, LinkError::EncryptionFailed(_)));
    assert!(link_err.to_string().contains("decryption failed"));
}

#[test]
fn link_error_from_identity_error() {
    let id_err = IdentityError::NoPrivateKey;
    let link_err: LinkError = id_err.into();
    assert!(matches!(link_err, LinkError::IdentityError(_)));
}

#[test]
fn link_error_from_packet_error() {
    let pkt_err = PacketError::InvalidHeaderType(0xFF);
    let link_err: LinkError = pkt_err.into();
    assert!(matches!(link_err, LinkError::PacketError(_)));
}

#[test]
fn channel_error_display_not_ready() {
    let err = ChannelError::NotReady;
    assert_eq!(err.to_string(), "channel not ready");
}

#[test]
fn channel_error_display_message_too_large() {
    let err = ChannelError::MessageTooLarge {
        size: 1024,
        max: 512,
    };
    assert_eq!(err.to_string(), "message too large: 1024 bytes (max 512)");
}

#[test]
fn channel_error_from_link_error() {
    let link_err = LinkError::InvalidProof;
    let chan_err: ChannelError = link_err.into();
    assert!(matches!(chan_err, ChannelError::LinkError(_)));
}

#[test]
fn resource_error_from_link_error() {
    let link_err = LinkError::NoPrivateKey;
    let res_err: ResourceError = link_err.into();
    assert!(matches!(res_err, ResourceError::LinkError(_)));
}

#[test]
fn resource_error_from_channel_error() {
    let chan_err = ChannelError::NotReady;
    let res_err: ResourceError = chan_err.into();
    assert!(matches!(res_err, ResourceError::ChannelError(_)));
}

#[test]
fn buffer_error_from_channel_error() {
    let chan_err = ChannelError::NotReady;
    let buf_err: BufferError = chan_err.into();
    assert!(matches!(buf_err, BufferError::ChannelError(_)));
}

#[test]
fn request_error_from_link_error() {
    let link_err = LinkError::InvalidProof;
    let req_err: RequestError = link_err.into();
    assert!(matches!(req_err, RequestError::LinkError(_)));
}

#[test]
fn request_error_from_resource_error() {
    let res_err = ResourceError::Timeout;
    let req_err: RequestError = res_err.into();
    assert!(matches!(req_err, RequestError::ResourceError(_)));
}

#[test]
fn request_error_display_timeout() {
    let err = RequestError::Timeout;
    assert_eq!(err.to_string(), "request timed out");
}

#[test]
fn resource_error_display_too_large() {
    let err = ResourceError::TooLarge(999999);
    assert_eq!(err.to_string(), "resource too large: 999999 bytes");
}

#[test]
fn buffer_error_display_closed() {
    let err = BufferError::Closed;
    assert_eq!(err.to_string(), "buffer closed");
}

// ---------------------------------------------------------------------------
// Remaining Display/From coverage
// ---------------------------------------------------------------------------

#[test]
fn link_error_display_remaining() {
    let err = LinkError::SignatureVerificationFailed;
    assert_eq!(err.to_string(), "signature verification failed");

    let err = LinkError::NoPrivateKey;
    assert_eq!(err.to_string(), "no private key available");
}

#[test]
fn channel_error_display_remaining() {
    let err = ChannelError::EnvelopeTooShort {
        actual: 3,
        min: 6,
    };
    assert_eq!(err.to_string(), "envelope too short: 3 bytes (minimum 6)");

    let err = ChannelError::EnvelopeLengthMismatch {
        header_says: 100,
        actual: 1,
    };
    assert_eq!(
        err.to_string(),
        "envelope length mismatch: header says 100 payload bytes but got 1"
    );

    let err = ChannelError::SequenceError {
        expected: 10,
        actual: 20,
    };
    assert_eq!(err.to_string(), "sequence error: expected 10, got 20");
}

#[test]
fn resource_error_display_all() {
    let variants: Vec<ResourceError> = vec![
        ResourceError::TooLarge(999),
        ResourceError::InvalidAdvertisement("bad adv".into()),
        ResourceError::InvalidPartHash(3),
        ResourceError::TransferFailed("timeout".into()),
        ResourceError::ProofFailed,
        ResourceError::Timeout,
        ResourceError::DecryptionFailed("bad key".into()),
        ResourceError::DecompressionFailed("corrupt".into()),
        ResourceError::InvalidMetadata("bad format".into()),
        ResourceError::HashMismatch {
            expected: "aabb".into(),
            actual: "ccdd".into(),
        },
        ResourceError::InvalidPayload("too short".into()),
    ];
    for v in &variants {
        let msg = v.to_string();
        assert!(!msg.is_empty(), "{v:?} should have non-empty Display");
    }
}

#[test]
fn buffer_error_display_remaining() {
    let err = BufferError::InvalidStreamHeader;
    assert_eq!(err.to_string(), "invalid stream header");

    let err = BufferError::CompressionFailed("out of memory".into());
    assert_eq!(err.to_string(), "compression failed: out of memory");

    let err = BufferError::DecompressionFailed("corrupt data".into());
    assert_eq!(err.to_string(), "decompression failed: corrupt data");
}

#[test]
fn request_error_display_remaining() {
    let err = RequestError::Failed("server error".into());
    assert_eq!(err.to_string(), "request failed: server error");

    let err = RequestError::TooLarge;
    assert_eq!(err.to_string(), "request payload too large");

    // Test From<ResourceError>
    let res_err = ResourceError::Timeout;
    let req_err: RequestError = res_err.into();
    assert!(matches!(req_err, RequestError::ResourceError(_)));
}
