//! Streaming HDLC frame accumulator for byte streams.
//!
//! Provides a stateful buffer that accumulates bytes and extracts complete
//! HDLC-delimited frames, matching the Python reference `read_loop` behavior.
//! Used by both TCP and Local interfaces.

use reticulum_core::constants::HEADER_MINSIZE;
use reticulum_core::framing::hdlc::{ESC, ESC_MASK, FLAG};

/// Stateful accumulator that buffers stream data and extracts complete
/// HDLC frames delimited by FLAG (0x7E) bytes.
///
/// Matches Python reference behavior:
/// - Scans for pairs of FLAG delimiters
/// - Unescapes content between delimiters
/// - Discards frames smaller than `HEADER_MINSIZE` (19 bytes)
/// - Retains trailing FLAG as potential start of next frame
pub struct HdlcFrameAccumulator {
    buffer: Vec<u8>,
}

impl HdlcFrameAccumulator {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
        }
    }

    /// Feed new data from the stream and extract all complete frames.
    ///
    /// Returns a `Vec` of unescaped frame payloads (without FLAG delimiters).
    /// Frames smaller than `HEADER_MINSIZE` are silently discarded.
    pub fn feed(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.buffer.extend_from_slice(data);

        let mut frames = Vec::new();

        while let Some(frame_start) = self.buffer.iter().position(|&b| b == FLAG) {
            // Find closing FLAG (starting after the opening one)
            let Some(offset) = self.buffer[frame_start + 1..]
                .iter()
                .position(|&b| b == FLAG)
            else {
                break;
            };
            let frame_end = frame_start + 1 + offset;

            // Extract inner content between the two FLAGs
            let inner = &self.buffer[frame_start + 1..frame_end];

            // Unescape the inner content
            let unescaped = hdlc_unescape(inner);

            // Only accept frames at least HEADER_MINSIZE bytes
            if unescaped.len() >= HEADER_MINSIZE {
                frames.push(unescaped);
            }

            // Keep data from frame_end onward (the closing FLAG may be
            // the opening FLAG of the next frame — matching Python's
            // `frame_buffer = frame_buffer[frame_end:]`)
            self.buffer = self.buffer[frame_end..].to_vec();
        }

        frames
    }
}

impl Default for HdlcFrameAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Unescape HDLC byte-stuffed content (inner bytes between FLAG delimiters).
///
/// Matching Python reference unescape order:
/// - ESC + (FLAG ^ ESC_MASK) → FLAG
/// - ESC + (ESC ^ ESC_MASK)  → ESC
fn hdlc_unescape(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == ESC && i + 1 < data.len() {
            result.push(data[i + 1] ^ ESC_MASK);
            i += 2;
        } else {
            result.push(data[i]);
            i += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::framing::hdlc::hdlc_frame;

    /// Helper: create a fake packet of `n` bytes (all 0xAA).
    fn fake_packet(n: usize) -> Vec<u8> {
        vec![0xAA; n]
    }

    #[test]
    fn single_complete_frame() {
        let mut acc = HdlcFrameAccumulator::new();
        let payload = fake_packet(HEADER_MINSIZE);
        let framed = hdlc_frame(&payload);

        let frames = acc.feed(&framed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], payload);
    }

    #[test]
    fn frame_split_across_two_reads() {
        let mut acc = HdlcFrameAccumulator::new();
        let payload = fake_packet(HEADER_MINSIZE);
        let framed = hdlc_frame(&payload);

        let mid = framed.len() / 2;

        let frames1 = acc.feed(&framed[..mid]);
        assert!(frames1.is_empty());

        let frames2 = acc.feed(&framed[mid..]);
        assert_eq!(frames2.len(), 1);
        assert_eq!(frames2[0], payload);
    }

    #[test]
    fn multiple_frames_in_one_read() {
        let mut acc = HdlcFrameAccumulator::new();
        let p1 = fake_packet(HEADER_MINSIZE);
        let p2 = fake_packet(HEADER_MINSIZE + 10);

        let mut data = hdlc_frame(&p1);
        data.extend_from_slice(&hdlc_frame(&p2));

        let frames = acc.feed(&data);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], p1);
        assert_eq!(frames[1], p2);
    }

    #[test]
    fn escape_sequences_handled() {
        let mut acc = HdlcFrameAccumulator::new();
        // Payload containing FLAG and ESC bytes that get escaped
        let mut payload = fake_packet(HEADER_MINSIZE - 2);
        payload.push(FLAG); // will be escaped
        payload.push(ESC); // will be escaped

        let framed = hdlc_frame(&payload);
        let frames = acc.feed(&framed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], payload);
    }

    #[test]
    fn too_small_frames_discarded() {
        let mut acc = HdlcFrameAccumulator::new();
        let small_payload = fake_packet(HEADER_MINSIZE - 1);
        let framed = hdlc_frame(&small_payload);

        let frames = acc.feed(&framed);
        assert!(frames.is_empty());
    }

    #[test]
    fn consecutive_flags_no_crash() {
        let mut acc = HdlcFrameAccumulator::new();
        // Several consecutive FLAGs with no content between them
        let data = vec![FLAG, FLAG, FLAG, FLAG];
        let frames = acc.feed(&data);
        assert!(frames.is_empty());
    }

    #[test]
    fn shared_flag_between_frames() {
        let mut acc = HdlcFrameAccumulator::new();
        let p1 = fake_packet(HEADER_MINSIZE);
        let p2 = fake_packet(HEADER_MINSIZE + 5);

        // Build two frames that share the middle FLAG:
        // FLAG + escape(p1) + FLAG + escape(p2) + FLAG
        // The closing FLAG of p1 is the opening FLAG of p2.
        let escaped1 = reticulum_core::framing::hdlc::hdlc_escape(&p1);
        let escaped2 = reticulum_core::framing::hdlc::hdlc_escape(&p2);

        let mut data = vec![FLAG];
        data.extend_from_slice(&escaped1);
        data.push(FLAG); // shared
        data.extend_from_slice(&escaped2);
        data.push(FLAG);

        let frames = acc.feed(&data);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], p1);
        assert_eq!(frames[1], p2);
    }

    #[test]
    fn partial_frame_retained_across_feeds() {
        let mut acc = HdlcFrameAccumulator::new();
        let payload = fake_packet(HEADER_MINSIZE);
        let framed = hdlc_frame(&payload);

        // Feed everything except the last byte (closing FLAG)
        let frames1 = acc.feed(&framed[..framed.len() - 1]);
        assert!(frames1.is_empty());

        // Feed the closing FLAG
        let frames2 = acc.feed(&framed[framed.len() - 1..]);
        assert_eq!(frames2.len(), 1);
        assert_eq!(frames2[0], payload);
    }

    #[test]
    fn garbage_before_frame_discarded() {
        let mut acc = HdlcFrameAccumulator::new();
        let payload = fake_packet(HEADER_MINSIZE);
        let framed = hdlc_frame(&payload);

        let mut data = vec![0x01, 0x02, 0x03]; // garbage
        data.extend_from_slice(&framed);

        let frames = acc.feed(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], payload);
    }
}
