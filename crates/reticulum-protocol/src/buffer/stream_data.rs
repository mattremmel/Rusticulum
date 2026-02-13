//! Stream data message types for the buffer protocol.
//!
//! Wraps binary chunks with a 2-byte stream header encoding stream ID, EOF,
//! and compression flags. Supports bz2 compression with a multi-try heuristic.

use bzip2::Compression;
use bzip2::read::{BzDecoder, BzEncoder};
use std::io::Read;

use crate::error::BufferError;

use super::constants::*;

/// 2-byte stream header encoding stream_id (14 bits), EOF (bit 15), and compression (bit 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeader {
    /// Stream identifier (0-16383).
    pub stream_id: u16,
    /// End-of-file flag.
    pub is_eof: bool,
    /// Data is bz2-compressed.
    pub is_compressed: bool,
}

impl StreamHeader {
    /// Encode the header as 2 big-endian bytes.
    pub fn encode(&self) -> [u8; 2] {
        let mut val = self.stream_id & STREAM_ID_MAX;
        if self.is_eof {
            val |= 0x8000;
        }
        if self.is_compressed {
            val |= 0x4000;
        }

        tracing::trace!(
            stream_id = self.stream_id,
            is_eof = self.is_eof,
            is_compressed = self.is_compressed,
            "encoding stream header"
        );

        val.to_be_bytes()
    }

    /// Decode a header from raw bytes (at least 2 bytes required).
    pub fn decode(bytes: &[u8]) -> Result<Self, BufferError> {
        if bytes.len() < 2 {
            return Err(BufferError::InvalidStreamHeader);
        }

        let val = u16::from_be_bytes([bytes[0], bytes[1]]);
        let is_eof = (val & 0x8000) != 0;
        let is_compressed = (val & 0x4000) != 0;
        let stream_id = val & STREAM_ID_MAX;

        tracing::trace!(stream_id, is_eof, is_compressed, "decoded stream header");

        Ok(Self {
            stream_id,
            is_eof,
            is_compressed,
        })
    }
}

/// A stream data message: header + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDataMessage {
    /// Stream header with ID, EOF, and compression flags.
    pub header: StreamHeader,
    /// Payload data (compressed if header.is_compressed).
    pub data: Vec<u8>,
}

impl StreamDataMessage {
    /// Pack the message into wire format: header(2) || data.
    pub fn pack(&self) -> Vec<u8> {
        let header_bytes = self.header.encode();
        let mut buf = Vec::with_capacity(2 + self.data.len());
        buf.extend_from_slice(&header_bytes);
        buf.extend_from_slice(&self.data);

        tracing::debug!(
            stream_id = self.header.stream_id,
            data_len = self.data.len(),
            is_eof = self.header.is_eof,
            is_compressed = self.header.is_compressed,
            "packed stream data message"
        );

        buf
    }

    /// Unpack a message from raw bytes. If compressed, decompresses the data.
    pub fn unpack(raw: &[u8]) -> Result<Self, BufferError> {
        let header = StreamHeader::decode(raw)?;
        let mut data = raw[2..].to_vec();

        if header.is_compressed {
            let mut decoder = BzDecoder::new(&data[..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| BufferError::DecompressionFailed(e.to_string()))?;
            data = decompressed;
        }

        tracing::debug!(
            stream_id = header.stream_id,
            data_len = data.len(),
            is_eof = header.is_eof,
            is_compressed = header.is_compressed,
            "unpacked stream data message"
        );

        Ok(Self { header, data })
    }
}

/// Attempt to compress data using bz2 with a multi-try heuristic.
///
/// Returns `Some((compressed_data, segment_length))` on success,
/// or `None` if compression doesn't help or data is too small.
pub fn compress_chunk(data: &[u8], max_data_len: usize) -> Option<(Vec<u8>, usize)> {
    if data.len() <= COMPRESSION_SKIP_THRESHOLD {
        return None;
    }

    for comp_try in 1..COMPRESSION_TRIES {
        let segment_length = data.len() / comp_try;
        let segment = &data[..segment_length];

        let mut encoder = BzEncoder::new(segment, Compression::best());
        let mut compressed = Vec::new();
        if encoder.read_to_end(&mut compressed).is_err() {
            tracing::trace!(
                comp_try,
                segment_length,
                "compression attempt failed (io error)"
            );
            continue;
        }

        let compressed_len = compressed.len();

        tracing::trace!(
            comp_try,
            segment_length,
            compressed_len,
            fits = compressed_len < max_data_len,
            smaller = compressed_len < segment_length,
            "compression attempt"
        );

        if compressed_len < max_data_len && compressed_len < segment_length {
            return Some((compressed, segment_length));
        }
    }

    None
}

/// Write a chunk of data as a stream data message.
///
/// Returns the packed message and the number of input bytes consumed.
pub fn write_chunk(stream_id: u16, data: &[u8], eof: bool) -> (StreamDataMessage, usize) {
    let data = if data.len() > MAX_CHUNK_LEN {
        &data[..MAX_CHUNK_LEN]
    } else {
        data
    };

    if let Some((compressed, segment_length)) = compress_chunk(data, MAX_DATA_LEN) {
        let msg = StreamDataMessage {
            header: StreamHeader {
                stream_id,
                is_eof: eof,
                is_compressed: true,
            },
            data: compressed,
        };
        (msg, segment_length)
    } else {
        let take = data.len().min(MAX_DATA_LEN);
        let msg = StreamDataMessage {
            header: StreamHeader {
                stream_id,
                is_eof: eof,
                is_compressed: false,
            },
            data: data[..take].to_vec(),
        };
        (msg, take)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Envelope;

    fn load_vectors() -> reticulum_test_vectors::buffer_transfers::BufferTransfersVectors {
        reticulum_test_vectors::buffer_transfers::load()
    }

    #[test]
    fn test_small_transfer_stream_packing() {
        let vectors = load_vectors();

        for tv in &vectors.small_transfer_vectors {
            for msg in &tv.messages {
                let expected_stream_packed = hex::decode(&msg.stream_packed_hex).unwrap();
                let chunk_data = hex::decode(&msg.chunk_hex).unwrap();

                let is_eof = msg.is_eof.unwrap_or(false);
                let stream_msg = StreamDataMessage {
                    header: StreamHeader {
                        stream_id: tv.stream_id as u16,
                        is_eof,
                        is_compressed: msg.compressed,
                    },
                    data: chunk_data.clone(),
                };

                let packed = stream_msg.pack();
                assert_eq!(
                    packed, expected_stream_packed,
                    "stream packing mismatch for vector index={}, sequence={}",
                    tv.index, msg.sequence
                );
                assert_eq!(packed.len(), msg.stream_packed_length as usize);
            }
        }
    }

    #[test]
    fn test_small_transfer_envelope_packing() {
        let vectors = load_vectors();

        for tv in &vectors.small_transfer_vectors {
            for msg in &tv.messages {
                let expected_envelope = hex::decode(&msg.envelope_packed_hex).unwrap();
                let chunk_data = hex::decode(&msg.chunk_hex).unwrap();

                let is_eof = msg.is_eof.unwrap_or(false);
                let stream_msg = StreamDataMessage {
                    header: StreamHeader {
                        stream_id: tv.stream_id as u16,
                        is_eof,
                        is_compressed: msg.compressed,
                    },
                    data: chunk_data,
                };

                let stream_packed = stream_msg.pack();
                let envelope = Envelope {
                    msg_type: SMT_STREAM_DATA,
                    sequence: msg.sequence as u16,
                    payload: stream_packed,
                };

                let envelope_packed = envelope.pack();
                assert_eq!(
                    envelope_packed, expected_envelope,
                    "envelope packing mismatch for vector index={}, sequence={}",
                    tv.index, msg.sequence
                );
                assert_eq!(envelope_packed.len(), msg.envelope_packed_length as usize);
            }
        }
    }

    #[test]
    fn test_eof_vectors() {
        let vectors = load_vectors();

        for tv in &vectors.eof_vectors {
            // Verify header encoding with eof=true
            let expected_header_hex = tv.eof_header_hex.trim_start_matches("0x");
            let expected_header_bytes = hex::decode(expected_header_hex).unwrap();

            let header = StreamHeader {
                stream_id: tv.stream_id as u16,
                is_eof: true,
                is_compressed: false,
            };
            let encoded = header.encode();
            assert_eq!(
                &encoded[..],
                &expected_header_bytes[..],
                "eof header mismatch for vector index={}",
                tv.index
            );

            // Verify the eof_message stream packing
            let eof_msg = &tv.eof_message;
            let expected_stream_packed = hex::decode(&eof_msg.stream_packed_hex).unwrap();

            let stream_msg = StreamDataMessage {
                header,
                data: vec![],
            };
            let packed = stream_msg.pack();
            assert_eq!(
                packed, expected_stream_packed,
                "eof stream packing mismatch for vector index={}",
                tv.index
            );
        }
    }

    #[test]
    fn test_compression_vectors() {
        let vectors = load_vectors();

        for tv in &vectors.compression_vectors {
            let input_data = if let Some(ref hex_str) = tv.input_data_hex {
                // Handle truncated hex strings with "... (N bytes total)"
                if hex_str.contains("...") {
                    // This is a display-only field; generate the data from description
                    // For the 500B compressible test, it's repeated 'Z' (0x5a)
                    vec![0x5a_u8; tv.input_data_length as usize]
                } else {
                    hex::decode(hex_str).unwrap()
                }
            } else {
                // No input hex — generate from description (index 11: partially compressible)
                // The test vector says input_data_length=16384 with a known sha256
                // We need to generate this deterministically.
                // For index 11, it's "partially compressible" — we can't test compression
                // output without exact input, so skip the compression match for this vector.
                continue;
            };

            assert_eq!(input_data.len(), tv.input_data_length as usize);

            let write_result = &tv.write_result;
            let expected_compressed = write_result.compressed;
            let expected_chunk_hex = &write_result.chunk_hex;
            let expected_stream_packed_hex = &write_result.stream_packed_hex;

            // Run write_chunk
            let (msg, processed_length) = write_chunk(tv.stream_id as u16, &input_data, false);

            assert_eq!(
                msg.header.is_compressed, expected_compressed,
                "compression flag mismatch for vector index={}",
                tv.index
            );
            assert_eq!(
                processed_length, write_result.processed_length as usize,
                "processed_length mismatch for vector index={}",
                tv.index
            );

            let expected_chunk = hex::decode(expected_chunk_hex).unwrap();
            assert_eq!(
                msg.data, expected_chunk,
                "chunk data mismatch for vector index={}",
                tv.index
            );

            let expected_stream_packed = hex::decode(expected_stream_packed_hex).unwrap();
            let packed = msg.pack();
            assert_eq!(
                packed, expected_stream_packed,
                "stream packing mismatch for vector index={}",
                tv.index
            );
        }
    }

    #[test]
    fn test_stream_header_roundtrip() {
        let vectors = load_vectors();

        // Roundtrip headers from small transfer vectors
        for tv in &vectors.small_transfer_vectors {
            for msg in &tv.messages {
                let packed = hex::decode(&msg.stream_packed_hex).unwrap();
                let header = StreamHeader::decode(&packed).unwrap();
                assert_eq!(header.stream_id, tv.stream_id as u16);
                assert_eq!(header.is_compressed, msg.compressed);
                assert_eq!(header.is_eof, msg.is_eof.unwrap_or(false));

                // Re-encode and verify first 2 bytes match
                let re_encoded = header.encode();
                assert_eq!(&re_encoded[..], &packed[..2]);
            }
        }

        // Roundtrip headers from EOF vectors
        for tv in &vectors.eof_vectors {
            let header = StreamHeader {
                stream_id: tv.stream_id as u16,
                is_eof: true,
                is_compressed: false,
            };
            let encoded = header.encode();
            let decoded = StreamHeader::decode(&encoded).unwrap();
            assert_eq!(decoded, header);
        }
    }

    #[test]
    fn test_unpack_decompresses() {
        // Test with the compressible vector (index 9): 500 bytes of 'Z'
        let vectors = load_vectors();
        let tv = &vectors.compression_vectors[1]; // index 9
        assert_eq!(tv.index, 9);

        let expected_stream_packed_hex = &tv.write_result.stream_packed_hex;
        let packed = hex::decode(expected_stream_packed_hex).unwrap();

        let msg = StreamDataMessage::unpack(&packed).unwrap();
        assert_eq!(msg.header.stream_id, 0);
        assert!(msg.header.is_compressed);
        assert!(!msg.header.is_eof);
        // After decompression, should be 500 bytes of 'Z'
        assert_eq!(msg.data.len(), 500);
        assert!(msg.data.iter().all(|&b| b == 0x5a));
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn proptest_stream_header_roundtrip(
                stream_id in 0u16..=STREAM_ID_MAX,
                is_eof in proptest::bool::ANY,
                is_compressed in proptest::bool::ANY,
            ) {
                let header = StreamHeader { stream_id, is_eof, is_compressed };
                let encoded = header.encode();
                let decoded = StreamHeader::decode(&encoded).unwrap();
                prop_assert_eq!(decoded.stream_id, stream_id);
                prop_assert_eq!(decoded.is_eof, is_eof);
                prop_assert_eq!(decoded.is_compressed, is_compressed);
            }

            #[test]
            fn proptest_stream_id_14bit(
                stream_id in 0u16..=u16::MAX,
                is_eof in proptest::bool::ANY,
                is_compressed in proptest::bool::ANY,
            ) {
                let header = StreamHeader { stream_id, is_eof, is_compressed };
                let encoded = header.encode();
                let decoded = StreamHeader::decode(&encoded).unwrap();
                // Stream ID should be masked to 14 bits
                prop_assert_eq!(decoded.stream_id, stream_id & STREAM_ID_MAX);
            }

            #[test]
            fn proptest_pack_unpack_roundtrip(
                data in proptest::collection::vec(any::<u8>(), 0..256),
                stream_id in 0u16..=STREAM_ID_MAX,
            ) {
                // Without compression flag, pack/unpack should roundtrip
                let msg = StreamDataMessage {
                    header: StreamHeader {
                        stream_id,
                        is_eof: false,
                        is_compressed: false,
                    },
                    data: data.clone(),
                };
                let packed = msg.pack();
                let unpacked = StreamDataMessage::unpack(&packed).unwrap();
                prop_assert_eq!(unpacked.header.stream_id, stream_id);
                prop_assert_eq!(unpacked.data, data);
            }
        }
    }
}
