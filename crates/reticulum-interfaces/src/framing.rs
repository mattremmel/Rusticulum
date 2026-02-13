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
///
/// The accumulator reuses internal buffers across calls to minimize
/// per-frame heap allocations. The main buffer is compacted in-place
/// via `drain` rather than reallocating, and a scratch buffer is reused
/// for HDLC unescaping.
pub struct HdlcFrameAccumulator {
    buffer: Vec<u8>,
    /// Scratch space reused for HDLC unescaping to avoid a fresh
    /// allocation per frame.
    unescape_buf: Vec<u8>,
}

impl HdlcFrameAccumulator {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
            unescape_buf: Vec::with_capacity(1024),
        }
    }

    /// Feed new data from the stream and extract all complete frames.
    ///
    /// Returns a `Vec` of unescaped frame payloads (without FLAG delimiters).
    /// Frames smaller than `HEADER_MINSIZE` are silently discarded.
    ///
    /// For zero-outer-allocation frame delivery, see [`feed_to`](Self::feed_to).
    pub fn feed(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        self.feed_to(data, |frame| frames.push(frame));
        frames
    }

    /// Feed new data from the stream and deliver each complete frame to a
    /// callback. This avoids allocating the outer `Vec<Vec<u8>>` returned
    /// by [`feed`](Self::feed), which is useful in read loops that forward
    /// frames one at a time.
    ///
    /// Frames smaller than `HEADER_MINSIZE` are silently discarded.
    pub fn feed_to(&mut self, data: &[u8], mut on_frame: impl FnMut(Vec<u8>)) {
        self.buffer.extend_from_slice(data);

        // Track how many bytes at the front of `buffer` have been consumed
        // so we can drain them all at once after the loop, instead of
        // reallocating the buffer on every frame.
        let mut consumed = 0;

        loop {
            let buf = &self.buffer[consumed..];

            let Some(frame_start) = buf.iter().position(|&b| b == FLAG) else {
                break;
            };

            // Find closing FLAG (starting after the opening one)
            let Some(offset) = buf[frame_start + 1..].iter().position(|&b| b == FLAG) else {
                break;
            };
            let frame_end = frame_start + 1 + offset;

            // Extract inner content between the two FLAGs
            let inner = &buf[frame_start + 1..frame_end];

            // Unescape into the reusable scratch buffer
            hdlc_unescape_into(inner, &mut self.unescape_buf);

            // Only accept frames at least HEADER_MINSIZE bytes
            if self.unescape_buf.len() >= HEADER_MINSIZE {
                on_frame(self.unescape_buf.clone());
            }

            // Advance past this frame. The closing FLAG may be the
            // opening FLAG of the next frame -- matching Python's
            // `frame_buffer = frame_buffer[frame_end:]`
            consumed += frame_end;
        }

        // Compact the buffer once, removing all consumed bytes.
        // `drain` shifts the remaining tail in-place without
        // reallocating the backing storage.
        if consumed > 0 {
            self.buffer.drain(..consumed);
        }
    }
}

impl Default for HdlcFrameAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Unescape HDLC byte-stuffed content into `out`, which is cleared first.
///
/// Matching Python reference unescape order:
/// - ESC + (FLAG ^ ESC_MASK) -> FLAG
/// - ESC + (ESC ^ ESC_MASK)  -> ESC
///
/// Reuses the capacity already present in `out` to avoid per-frame allocation.
fn hdlc_unescape_into(data: &[u8], out: &mut Vec<u8>) {
    out.clear();
    // Reserve enough space -- unescaped output is at most `data.len()` bytes.
    if out.capacity() < data.len() {
        out.reserve(data.len() - out.capacity());
    }
    let mut i = 0;
    while i < data.len() {
        if data[i] == ESC && i + 1 < data.len() {
            out.push(data[i + 1] ^ ESC_MASK);
            i += 2;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
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

    #[test]
    fn feed_to_callback_api() {
        let mut acc = HdlcFrameAccumulator::new();
        let p1 = fake_packet(HEADER_MINSIZE);
        let p2 = fake_packet(HEADER_MINSIZE + 10);

        let mut data = hdlc_frame(&p1);
        data.extend_from_slice(&hdlc_frame(&p2));

        let mut collected = Vec::new();
        acc.feed_to(&data, |frame| collected.push(frame));
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0], p1);
        assert_eq!(collected[1], p2);
    }

    #[test]
    fn buffer_reuse_across_multiple_feeds() {
        let mut acc = HdlcFrameAccumulator::new();

        // Feed several frames across multiple calls and verify buffer reuse
        for i in 0..10 {
            let payload = fake_packet(HEADER_MINSIZE + i);
            let framed = hdlc_frame(&payload);
            let frames = acc.feed(&framed);
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0], payload);
        }

        // The unescape_buf should have been reused (capacity >= last payload size)
        assert!(acc.unescape_buf.capacity() >= HEADER_MINSIZE);
    }
}
