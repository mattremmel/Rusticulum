//! Cross-implementation fuzz test generator and validator.
//!
//! Two modes:
//! - `generate <output_dir> [count] [seed]` — writes random protocol messages as JSON
//! - `validate <input_dir> <output_dir>` — reads JSON, parses each, writes results

use std::fs;
use std::path::{Path, PathBuf};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{json, Value};

use reticulum_core::announce::Announce;
use reticulum_core::framing::hdlc::hdlc_unframe;
use reticulum_core::framing::kiss::kiss_unframe;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::DestinationHash;
use reticulum_protocol::channel::envelope::Envelope;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: fuzz-gen generate <output_dir> [count] [seed]");
        eprintln!("       fuzz-gen validate <input_dir> <output_dir>");
        std::process::exit(1);
    }

    let mode = &args[1];
    match mode.as_str() {
        "generate" => {
            let output_dir = PathBuf::from(&args[2]);
            let count: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(50);
            let seed: u64 = std::env::var("FUZZ_SEED")
                .ok()
                .and_then(|s| s.parse().ok())
                .or_else(|| args.get(4).and_then(|s| s.parse().ok()))
                .unwrap_or(42);
            generate(&output_dir, count, seed);
        }
        "validate" => {
            if args.len() < 4 {
                eprintln!("Usage: fuzz-gen validate <input_dir> <output_dir>");
                std::process::exit(1);
            }
            let input_dir = PathBuf::from(&args[2]);
            let output_dir = PathBuf::from(&args[3]);
            validate(&input_dir, &output_dir);
        }
        _ => {
            eprintln!("Unknown mode: {mode}. Use 'generate' or 'validate'.");
            std::process::exit(1);
        }
    }
}

/// Generate random protocol messages and write as JSON files.
fn generate(output_dir: &Path, count: usize, seed: u64) {
    fs::create_dir_all(output_dir).expect("create output dir");
    let mut rng = StdRng::seed_from_u64(seed);

    let categories = ["packet", "announce", "hdlc", "kiss", "envelope"];
    let mut all_cases: Vec<Value> = Vec::new();

    for category in &categories {
        for i in 0..count {
            let raw = match *category {
                "packet" => gen_packet_bytes(&mut rng, i),
                "announce" => gen_announce_bytes(&mut rng, i),
                "hdlc" => gen_hdlc_bytes(&mut rng, i),
                "kiss" => gen_kiss_bytes(&mut rng, i),
                "envelope" => gen_envelope_bytes(&mut rng, i),
                _ => unreachable!(),
            };

            all_cases.push(json!({
                "index": all_cases.len(),
                "category": category,
                "raw_hex": hex::encode(&raw),
                "length": raw.len(),
            }));
        }
    }

    let output_path = output_dir.join("rust_inputs.json");
    let json_str = serde_json::to_string_pretty(&all_cases).expect("serialize");
    fs::write(&output_path, &json_str).expect("write rust_inputs.json");

    eprintln!(
        "fuzz-gen: generated {} cases ({} per category, seed={}) to {}",
        all_cases.len(),
        count,
        seed,
        output_path.display()
    );
}

/// Generate random packet bytes. Some have valid structure, some are pure random.
fn gen_packet_bytes(rng: &mut StdRng, index: usize) -> Vec<u8> {
    let len: usize = rng.gen_range(0..600);
    if index.is_multiple_of(5) && len >= 19 {
        // Valid H1 structure: flags(1) + hops(1) + dest(16) + ctx(1) + data
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        buf[0] &= 0x3F; // Clear header_type bits for H1
        buf[18] = *[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 250, 251, 252, 253, 254, 255]
            .get(rng.gen_range(0..21))
            .unwrap();
        buf
    } else {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        buf
    }
}

/// Generate random announce bytes. Some have valid layout.
fn gen_announce_bytes(rng: &mut StdRng, index: usize) -> Vec<u8> {
    let len: usize = rng.gen_range(0..512);
    if index.is_multiple_of(5) && len >= 148 {
        // Valid-ish layout: pubkey(64) + name_hash(10) + random_hash(10) + signature(64)
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        buf
    } else {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        buf
    }
}

/// Generate random HDLC bytes. Some have proper FLAG delimiters.
fn gen_hdlc_bytes(rng: &mut StdRng, index: usize) -> Vec<u8> {
    let len: usize = rng.gen_range(0..256);
    if index.is_multiple_of(5) && len >= 2 {
        // Wrap with HDLC flags
        let mut buf = vec![0x7E];
        let inner_len = len.saturating_sub(2);
        let mut inner = vec![0u8; inner_len];
        rng.fill(&mut inner[..]);
        buf.extend_from_slice(&inner);
        buf.push(0x7E);
        buf
    } else {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        buf
    }
}

/// Generate random KISS bytes. Some have proper FEND delimiters.
fn gen_kiss_bytes(rng: &mut StdRng, index: usize) -> Vec<u8> {
    let len: usize = rng.gen_range(0..256);
    if index.is_multiple_of(5) && len >= 3 {
        // Wrap with KISS FEND + CMD_DATA
        let mut buf = vec![0xC0, 0x00]; // FEND + CMD_DATA
        let inner_len = len.saturating_sub(3);
        let mut inner = vec![0u8; inner_len];
        rng.fill(&mut inner[..]);
        buf.extend_from_slice(&inner);
        buf.push(0xC0); // FEND
        buf
    } else {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        buf
    }
}

/// Generate random envelope bytes. Some have valid 6-byte header.
fn gen_envelope_bytes(rng: &mut StdRng, index: usize) -> Vec<u8> {
    if index.is_multiple_of(5) {
        // Valid structure: msg_type(2) + sequence(2) + length(2) + payload
        let payload_len: u16 = rng.gen_range(0..64);
        let mut buf = Vec::with_capacity(6 + payload_len as usize);
        let msg_type: u16 = rng.gen_range(0..=u16::MAX);
        let sequence: u16 = rng.gen_range(0..=u16::MAX);
        buf.extend_from_slice(&msg_type.to_be_bytes());
        buf.extend_from_slice(&sequence.to_be_bytes());
        buf.extend_from_slice(&payload_len.to_be_bytes());
        let mut payload = vec![0u8; payload_len as usize];
        rng.fill(&mut payload[..]);
        buf.extend_from_slice(&payload);
        buf
    } else {
        let len: usize = rng.gen_range(0..128);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        buf
    }
}

/// Validate inputs from another implementation.
fn validate(input_dir: &Path, output_dir: &Path) {
    fs::create_dir_all(output_dir).expect("create output dir");

    let input_path = input_dir.join("python_inputs.json");
    eprintln!("fuzz-gen: waiting for {}", input_path.display());

    // Wait for input file (up to 90s)
    for _ in 0..180 {
        if input_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    if !input_path.exists() {
        eprintln!("fuzz-gen: timeout waiting for python_inputs.json");
        std::process::exit(1);
    }

    let content = fs::read_to_string(&input_path).expect("read python_inputs.json");
    let cases: Vec<Value> = serde_json::from_str(&content).expect("parse python_inputs.json");

    let mut results: Vec<Value> = Vec::new();
    let mut crashes = 0u32;

    for case in &cases {
        let index = case["index"].as_u64().unwrap_or(0);
        let category = case["category"].as_str().unwrap_or("unknown");
        let raw_hex = case["raw_hex"].as_str().unwrap_or("");
        let raw = match hex::decode(raw_hex) {
            Ok(b) => b,
            Err(e) => {
                results.push(json!({
                    "index": index,
                    "result": "error",
                    "error_msg": format!("hex decode error: {e}"),
                }));
                continue;
            }
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            validate_case(category, &raw)
        }));

        match result {
            Ok(outcome) => {
                results.push(json!({
                    "index": index,
                    "result": outcome.0,
                    "error_msg": outcome.1,
                }));
            }
            Err(_) => {
                crashes += 1;
                results.push(json!({
                    "index": index,
                    "result": "crash",
                    "error_msg": "PANIC in Rust parser",
                }));
            }
        }
    }

    let output_path = output_dir.join("rust_results.json");
    let json_str = serde_json::to_string_pretty(&results).expect("serialize");
    fs::write(&output_path, &json_str).expect("write rust_results.json");

    let total = cases.len();
    let ok_count = results.iter().filter(|r| r["result"] == "ok").count();
    let err_count = results.iter().filter(|r| r["result"] == "error").count();

    eprintln!(
        "fuzz-gen: validated {} cases: {} ok, {} error, {} crashes",
        total, ok_count, err_count, crashes
    );
    eprintln!("fuzz_validation_complete");

    if crashes > 0 {
        std::process::exit(1);
    }
}

/// Validate a single test case through the appropriate parser.
fn validate_case(category: &str, raw: &[u8]) -> (&'static str, String) {
    match category {
        "packet" => match RawPacket::parse(raw) {
            Ok(_) => ("ok", String::new()),
            Err(e) => ("error", format!("{e}")),
        },
        "announce" => match Announce::from_raw_packet(raw) {
            Ok(_) => ("ok", String::new()),
            Err(e) => ("error", format!("{e}")),
        },
        "announce_payload" => {
            let dh = if raw.len() >= 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&raw[..16]);
                arr
            } else {
                [0u8; 16]
            };
            let payload = if raw.len() > 16 { &raw[16..] } else { &[] };
            match Announce::from_payload(
                DestinationHash::new(dh),
                false,
                reticulum_core::packet::context::ContextType::None,
                payload,
            ) {
                Ok(_) => ("ok", String::new()),
                Err(e) => ("error", format!("{e}")),
            }
        }
        "hdlc" => match hdlc_unframe(raw) {
            Ok(_) => ("ok", String::new()),
            Err(e) => ("error", format!("{e}")),
        },
        "kiss" => match kiss_unframe(raw) {
            Ok(_) => ("ok", String::new()),
            Err(e) => ("error", format!("{e}")),
        },
        "envelope" => match Envelope::unpack(raw) {
            Ok(_) => ("ok", String::new()),
            Err(e) => ("error", format!("{e}")),
        },
        _ => ("error", format!("unknown category: {category}")),
    }
}
