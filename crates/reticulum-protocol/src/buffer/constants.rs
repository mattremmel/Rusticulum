//! Buffer stream protocol constants.

/// System message type for stream data.
pub const SMT_STREAM_DATA: u16 = 0xFF00;

/// Stream data overhead: 2 (stream header) + 6 (channel envelope).
pub const STREAM_DATA_OVERHEAD: usize = 8;

/// Maximum payload data length per message: LINK_MDU(431) - OVERHEAD(8).
pub const MAX_DATA_LEN: usize = 423;

/// Maximum input chunk length per write call.
pub const MAX_CHUNK_LEN: usize = 16384;

/// Number of compression attempts (loop tries 1..COMPRESSION_TRIES-1, i.e. 1, 2, 3).
pub const COMPRESSION_TRIES: usize = 4;

/// Compression is skipped if chunk length is at or below this threshold.
pub const COMPRESSION_SKIP_THRESHOLD: usize = 32;

/// Maximum stream ID value (14-bit).
pub const STREAM_ID_MAX: u16 = 0x3FFF;

/// Bit flag for EOF in stream header (bit 15).
pub const STREAM_EOF_FLAG: u16 = 0x8000;

/// Bit flag for compression in stream header (bit 14).
pub const STREAM_COMPRESSED_FLAG: u16 = 0x4000;
