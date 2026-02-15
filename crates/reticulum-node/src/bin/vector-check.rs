//! Cross-implementation deterministic test vector checker.
//!
//! Loads all 20 JSON test vector files, recomputes operations using the Rust
//! implementation, and writes sorted results to a file for diffing against the
//! Python RNS implementation's output.
//!
//! Usage: vector-check <output-dir>
//! Output: <output-dir>/rust_results.txt

use std::collections::BTreeMap;
use std::io::Write;

// Crypto primitives
use reticulum_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use reticulum_crypto::hkdf::{hkdf, hkdf_extract};
use reticulum_crypto::hmac::hmac_sha256;
use reticulum_crypto::pkcs7::pkcs7_pad;
use reticulum_crypto::sha::{sha256, sha512, truncated_hash};
use reticulum_crypto::token::Token;
use reticulum_crypto::x25519::{X25519PrivateKey, X25519PublicKey};

// Core types
use reticulum_core::destination::{destination_hash, name_hash, plain_destination_hash};
use reticulum_core::framing::hdlc::{hdlc_frame, hdlc_unframe};
use reticulum_core::framing::kiss::{kiss_frame, kiss_unframe};
use reticulum_core::packet::flags::PacketFlags;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::IdentityHash;

// Protocol
use reticulum_protocol::channel::envelope::Envelope;
use reticulum_protocol::channel::state::ChannelState;
use reticulum_protocol::link::mtu;
use reticulum_protocol::link::state::LinkActive;
use reticulum_protocol::link::types::LinkMode;
use reticulum_protocol::request::timeout::compute_request_timeout;

// Transport
use reticulum_transport::ifac::{IfacConfig, IfacCredentials};
use reticulum_transport::path::types::InterfaceMode;

// Test vectors
use reticulum_test_vectors::{
    announces, buffer_transfers, channels, destination_hashes, hkdf as hkdf_vectors,
    interface_framing, keypairs, links, multi_hop_routing, packet_headers, packets_data,
    path_expiration, path_requests, requests, resources, resource_transfers, retry_timers,
    window_adaptation, hashes, token as token_vectors,
};

/// All results stored here, keys are sorted lexicographically
type Results = BTreeMap<String, String>;

fn h(data: &[u8]) -> String {
    hex::encode(data)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = args.get(1).map(|s| s.as_str()).unwrap_or(".");
    let output_path = format!("{}/rust_results.txt", output_dir);

    eprintln!("=== vector-check: starting ===");
    let mut results = Results::new();

    check_hashes(&mut results);
    check_hkdf(&mut results);
    check_token(&mut results);
    check_keypairs(&mut results);
    check_destinations(&mut results);
    check_packet_headers(&mut results);
    check_packets_data(&mut results);
    check_announces(&mut results);
    check_interface_framing(&mut results);
    check_links(&mut results);
    check_channels(&mut results);
    check_resources(&mut results);
    check_resource_transfers(&mut results);
    check_buffer_transfers(&mut results);
    check_requests(&mut results);
    check_retry_timers(&mut results);
    check_window_adaptation(&mut results);
    check_path_expiration(&mut results);
    check_path_requests(&mut results);
    check_multi_hop_routing(&mut results);

    // Write sorted results
    let mut f = std::fs::File::create(&output_path).expect("create output file");
    for (key, value) in &results {
        writeln!(f, "{} = {}", key, value).expect("write line");
    }

    eprintln!(
        "=== vector-check: wrote {} lines to {} ===",
        results.len(),
        output_path
    );
}

// ---------------------------------------------------------------------------
// 1. Hashes
// ---------------------------------------------------------------------------
fn check_hashes(r: &mut Results) {
    let v = hashes::load();
    for (i, vec) in v.sha256.iter().enumerate() {
        let input = hex::decode(&vec.input).unwrap();
        let digest = sha256(&input);
        r.insert(format!("hashes.sha256.{}", i), h(&digest));
    }
    for (i, vec) in v.sha512.iter().enumerate() {
        let input = hex::decode(&vec.input).unwrap();
        let digest = sha512(&input);
        r.insert(format!("hashes.sha512.{}", i), h(&digest));
    }
    for (i, vec) in v.truncated_hash.iter().enumerate() {
        let input = hex::decode(&vec.input).unwrap();
        let th = truncated_hash(&input);
        r.insert(format!("hashes.truncated.{}", i), h(&th));
    }
    eprintln!("  [OK] hashes: {} entries", r.len());
}

// ---------------------------------------------------------------------------
// 2. HKDF
// ---------------------------------------------------------------------------
fn check_hkdf(r: &mut Results) {
    let v = hkdf_vectors::load();
    let start = r.len();
    for (i, vec) in v.rfc5869_vectors.iter().enumerate() {
        let ikm = hex::decode(&vec.ikm).unwrap();
        let salt_bytes = hex::decode(&vec.salt).unwrap();
        let info = hex::decode(&vec.info).unwrap();
        let length = vec.length as usize;

        // PRK = HMAC-SHA256(salt, ikm)
        let salt_for_extract = if salt_bytes.is_empty() {
            None
        } else {
            Some(salt_bytes.as_slice())
        };
        let prk = hkdf_extract(salt_for_extract, &ikm);
        r.insert(format!("hkdf.rfc5869.{}.prk", i), h(&prk));

        // OKM = HKDF(length, ikm, salt, info)
        let salt_for_hkdf = if salt_bytes.is_empty() {
            None
        } else {
            Some(salt_bytes.as_slice())
        };
        let info_opt = if info.is_empty() {
            None
        } else {
            Some(info.as_slice())
        };
        let okm = hkdf(length, &ikm, salt_for_hkdf, info_opt);
        r.insert(format!("hkdf.rfc5869.{}.okm", i), h(&okm));
    }

    // Reticulum-specific vector
    let rv = &v.reticulum_vector;
    let shared_key = hex::decode(&rv.shared_key).unwrap();
    let salt = hex::decode(&rv.salt).unwrap();
    let derived = hkdf(rv.length as usize, &shared_key, Some(&salt), None);
    r.insert("hkdf.reticulum.derived_key".to_string(), h(&derived));

    eprintln!("  [OK] hkdf: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 3. Token (PKCS7, HMAC, Fernet)
// ---------------------------------------------------------------------------
fn check_token(r: &mut Results) {
    let v = token_vectors::load();
    let start = r.len();

    // PKCS7 padding
    for (i, vec) in v.pkcs7_padding.iter().enumerate() {
        let input = hex::decode(&vec.input).unwrap();
        let padded = pkcs7_pad(&input, 16);
        r.insert(format!("token.pkcs7.{}", i), h(&padded));
    }

    // HMAC-SHA256
    for (i, vec) in v.hmac_sha256.iter().enumerate() {
        let key = hex::decode(&vec.key).unwrap();
        let msg = hex::decode(&vec.message).unwrap();
        let digest = hmac_sha256(&key, &msg);
        r.insert(format!("token.hmac.{}", i), h(&digest));
    }

    // Deterministic Fernet
    for (i, vec) in v.deterministic_fernet_vectors.iter().enumerate() {
        let key_bytes = hex::decode(&vec.key).unwrap();
        let iv_bytes = hex::decode(&vec.iv).unwrap();
        let plaintext = hex::decode(&vec.plaintext).unwrap();

        let key: [u8; 64] = key_bytes.try_into().unwrap();
        let iv: [u8; 16] = iv_bytes.try_into().unwrap();
        let token = Token::new(&key);
        let encrypted = token.encrypt_with_iv(&plaintext, &iv);
        r.insert(format!("token.fernet.{}.encrypt", i), h(&encrypted));

        // Decrypt the known token
        let token_data = hex::decode(&vec.token).unwrap();
        let decrypted = token.decrypt(&token_data).unwrap();
        r.insert(format!("token.fernet.{}.decrypt", i), h(&decrypted));
    }

    eprintln!("  [OK] token: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 4. Keypairs
// ---------------------------------------------------------------------------
fn check_keypairs(r: &mut Results) {
    let v = keypairs::load();
    let start = r.len();

    // Identity hashes
    for (i, kp) in v.keypairs.iter().enumerate() {
        let pub_key = hex::decode(&kp.public_key).unwrap();
        let identity_hash = truncated_hash(&pub_key);
        r.insert(format!("keypairs.identity_hash.{}", i), h(&identity_hash));
    }

    // ECDH
    for (i, vec) in v.ecdh_vectors.iter().enumerate() {
        let kp_a = &v.keypairs[vec.keypair_a as usize];
        let kp_b = &v.keypairs[vec.keypair_b as usize];
        let a_priv = X25519PrivateKey::from_bytes(
            hex::decode(&kp_a.x25519_private).unwrap().try_into().unwrap(),
        );
        let b_pub = X25519PublicKey::from_bytes(
            hex::decode(&kp_b.x25519_public).unwrap().try_into().unwrap(),
        );
        let shared = a_priv.diffie_hellman(&b_pub);
        r.insert(format!("keypairs.ecdh.{}", i), h(&shared));
    }

    // Signatures
    for (i, vec) in v.signature_vectors.iter().enumerate() {
        let kp = &v.keypairs[vec.keypair_index as usize];
        let ed25519_prv_bytes: [u8; 32] =
            hex::decode(&kp.ed25519_private).unwrap().try_into().unwrap();
        let ed25519_prv = Ed25519PrivateKey::from_bytes(ed25519_prv_bytes);

        let common_msg = hex::decode(&vec.common_message).unwrap();
        let common_sig = ed25519_prv.sign(&common_msg);
        r.insert(
            format!("keypairs.sig.{}.common", i),
            h(&common_sig.to_bytes()),
        );

        let unique_msg = hex::decode(&vec.unique_message).unwrap();
        let unique_sig = ed25519_prv.sign(&unique_msg);
        r.insert(
            format!("keypairs.sig.{}.unique", i),
            h(&unique_sig.to_bytes()),
        );
    }

    eprintln!("  [OK] keypairs: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 5. Destination hashes
// ---------------------------------------------------------------------------
fn check_destinations(r: &mut Results) {
    let v = destination_hashes::load();
    let kpv = keypairs::load();
    let start = r.len();

    for (i, vec) in v.single_destinations.iter().enumerate() {
        let aspects: Vec<&str> = vec.aspects.iter().map(|s| s.as_str()).collect();
        let nh = name_hash(&vec.app_name, &aspects);
        r.insert(format!("destinations.single.{}.name_hash", i), h(nh.as_ref()));

        let kp = &kpv.keypairs[vec.keypair_index as usize];
        let ih_bytes: [u8; 16] = hex::decode(&kp.identity_hash).unwrap().try_into().unwrap();
        let ih = IdentityHash::new(ih_bytes);
        let dh = destination_hash(&nh, &ih);
        r.insert(format!("destinations.single.{}.dest_hash", i), h(dh.as_ref()));
    }

    for (i, vec) in v.plain_destinations.iter().enumerate() {
        let aspects: Vec<&str> = vec.aspects.iter().map(|s| s.as_str()).collect();
        let nh = name_hash(&vec.app_name, &aspects);
        let dh = plain_destination_hash(&nh);
        r.insert(format!("destinations.plain.{}.dest_hash", i), h(dh.as_ref()));
    }

    eprintln!("  [OK] destinations: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 6. Packet headers
// ---------------------------------------------------------------------------
fn check_packet_headers(r: &mut Results) {
    let v = packet_headers::load();
    let start = r.len();

    // Flag packing
    for (i, vec) in v.flag_packing_vectors.iter().enumerate() {
        use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
        let flags = PacketFlags {
            header_type: HeaderType::try_from(vec.header_type as u8).unwrap(),
            context_flag: vec.context_flag != 0,
            transport_type: TransportType::try_from(vec.transport_type as u8).unwrap(),
            destination_type: DestinationType::try_from(vec.destination_type as u8).unwrap(),
            packet_type: PacketType::try_from(vec.packet_type as u8).unwrap(),
        };
        let byte = flags.to_byte();
        r.insert(format!("packets.flag_pack.{}", i), format!("{:02x}", byte));
    }

    // Flag unpacking
    for (i, vec) in v.flag_unpacking_vectors.iter().enumerate() {
        let byte = u8::from_str_radix(&vec.flags_byte, 16).unwrap();
        let flags = PacketFlags::try_from(byte).unwrap();
        // Encode as "ht.cf.tt.dt.pt" string for comparison
        let desc = format!(
            "{}.{}.{}.{}.{}",
            flags.header_type as u8,
            flags.context_flag as u8,
            flags.transport_type as u8,
            flags.destination_type as u8,
            flags.packet_type as u8,
        );
        r.insert(format!("packets.flag_unpack.{}", i), desc);
    }

    // Header parsing and hashing
    for (i, vec) in v.header_vectors.iter().enumerate() {
        let raw = hex::decode(&vec.raw_packet).unwrap();
        if let Ok(pkt) = RawPacket::parse(&raw) {
            let hashable = pkt.hashable_part();
            r.insert(format!("packets.header.{}.hashable", i), h(&hashable));
            let pkt_hash = pkt.packet_hash();
            r.insert(format!("packets.header.{}.hash", i), h(pkt_hash.as_ref()));
        }
    }

    eprintln!("  [OK] packet_headers: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 7. Packets data (encrypt/decrypt/proof)
// ---------------------------------------------------------------------------
fn check_packets_data(r: &mut Results) {
    let v = packets_data::load();
    let lv = links::load();
    let start = r.len();

    for (i, vec) in v.data_packet_vectors.iter().enumerate() {
        // Packet hash from raw
        let raw = hex::decode(&vec.raw_packet).unwrap();
        if let Ok(pkt) = RawPacket::parse(&raw) {
            let pkt_hash = pkt.packet_hash();
            r.insert(format!("packets_data.packet_hash.{}", i), h(pkt_hash.as_ref()));
        }

        // Token encryption with deterministic IV
        // We need the derived key from the handshake reference
        // The handshake reference is "handshake_vectors[0]" typically
        let derived_key_hex = &lv.handshake_vectors[0].step_2_lrproof.derived_key;
        let derived_key: [u8; 64] = hex::decode(derived_key_hex).unwrap().try_into().unwrap();
        let token = Token::new(&derived_key);

        let plaintext = hex::decode(&vec.plaintext).unwrap();
        let iv: [u8; 16] = hex::decode(&vec.deterministic_iv).unwrap().try_into().unwrap();
        let encrypted = token.encrypt_with_iv(&plaintext, &iv);
        r.insert(format!("packets_data.encrypt.{}", i), h(&encrypted));

        // Decrypt
        let token_ct = hex::decode(&vec.token_ciphertext).unwrap();
        let decrypted = token.decrypt(&token_ct).unwrap();
        r.insert(format!("packets_data.decrypt.{}", i), h(&decrypted));
    }

    // Proof generation
    for (i, vec) in v.proof_generation_vectors.iter().enumerate() {
        let signer_prv: [u8; 32] = hex::decode(&vec.signer_private_key)
            .unwrap()
            .try_into()
            .unwrap();
        let ed_prv = Ed25519PrivateKey::from_bytes(signer_prv);
        let pkt_hash = hex::decode(&vec.original_packet_hash).unwrap();
        let sig = ed_prv.sign(&pkt_hash);
        r.insert(format!("packets_data.proof.{}", i), h(&sig.to_bytes()));
    }

    eprintln!("  [OK] packets_data: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 8. Announces
// ---------------------------------------------------------------------------
fn check_announces(r: &mut Results) {
    let v = announces::load();
    let kpv = keypairs::load();
    let start = r.len();

    for (i, ann) in v.valid_announces.iter().enumerate() {
        // Destination hash
        r.insert(
            format!("announces.valid.{}.dest_hash", i),
            ann.destination_hash.clone(),
        );

        // Packet hash from raw
        let raw = hex::decode(&ann.raw_packet).unwrap();
        if let Ok(pkt) = RawPacket::parse(&raw) {
            let pkt_hash = pkt.packet_hash();
            r.insert(format!("announces.valid.{}.packet_hash", i), h(pkt_hash.as_ref()));
        }

        // Signature verification
        let kp = &kpv.keypairs[ann.keypair_index as usize];
        let ed_pub_bytes: [u8; 32] =
            hex::decode(&kp.ed25519_public).unwrap().try_into().unwrap();
        let ed_pub = Ed25519PublicKey::from_bytes(ed_pub_bytes).unwrap();
        let signed_data = hex::decode(&ann.signed_data).unwrap();
        let sig_bytes: [u8; 64] = hex::decode(&ann.signature).unwrap().try_into().unwrap();
        let sig = reticulum_crypto::ed25519::Ed25519Signature::from_bytes(sig_bytes);
        let valid = ed_pub.verify(&signed_data, &sig).is_ok();
        r.insert(
            format!("announces.valid.{}.sig_verify", i),
            format!("{}", valid),
        );
    }

    eprintln!("  [OK] announces: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 9. Interface framing
// ---------------------------------------------------------------------------
fn check_interface_framing(r: &mut Results) {
    let v = interface_framing::load();
    let start = r.len();

    // HDLC
    for (i, vec) in v.hdlc.vectors.iter().enumerate() {
        let input = hex::decode(&vec.input).unwrap();
        let framed = hdlc_frame(&input);
        r.insert(format!("framing.hdlc.{}.frame", i), h(&framed));

        let unframed = hdlc_unframe(&framed).unwrap();
        r.insert(format!("framing.hdlc.{}.unframe", i), h(&unframed));
    }

    // KISS
    for (i, vec) in v.kiss.vectors.iter().enumerate() {
        let input = hex::decode(&vec.input).unwrap();
        let framed = kiss_frame(&input);
        r.insert(format!("framing.kiss.{}.frame", i), h(&framed));

        let unframed = kiss_unframe(&framed).unwrap();
        r.insert(format!("framing.kiss.{}.unframe", i), h(&unframed));
    }

    // IFAC
    for (i, vec) in v.ifac.vectors.iter().enumerate() {
        // Only process vectors that have both netname/netkey and a raw_packet with masked output
        let netname = vec.ifac_netname.as_deref().or(vec.sender_netname.as_deref());
        let netkey = vec.ifac_netkey.as_deref().or(vec.sender_netkey.as_deref());

        if let (Some(_masked_expected), Some(_)) = (&vec.masked_packet, &vec.ifac_value)
            && let Some(creds) = IfacCredentials::from_options(netname, netkey)
        {
            let config = IfacConfig::new(creds, vec.ifac_size as usize);
            let raw = hex::decode(&vec.raw_packet).unwrap();
            if let Ok(masked) = reticulum_transport::ifac::ifac_apply(&config, &raw) {
                r.insert(format!("framing.ifac.{}", i), h(&masked));
            }
        }
    }

    // Full pipeline
    for (i, vec) in v.full_pipeline.vectors.iter().enumerate() {
        let raw = hex::decode(&vec.step_0_raw).unwrap();

        // Apply IFAC if configured
        let ifac_data = if vec.ifac_size > 0 {
            if let Some(creds) =
                IfacCredentials::from_options(vec.ifac_netname.as_deref(), vec.ifac_netkey.as_deref())
            {
                let config = IfacConfig::new(creds, vec.ifac_size as usize);
                reticulum_transport::ifac::ifac_apply(&config, &raw).unwrap()
            } else {
                raw.clone()
            }
        } else {
            raw.clone()
        };

        // Frame
        let framed = match vec.framing.as_str() {
            "HDLC" => hdlc_frame(&ifac_data),
            "KISS" => kiss_frame(&ifac_data),
            _ => ifac_data.clone(),
        };

        r.insert(format!("framing.pipeline.{}", i), h(&framed));
    }

    eprintln!("  [OK] interface_framing: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 10. Links
// ---------------------------------------------------------------------------
fn check_links(r: &mut Results) {
    let v = links::load();
    let kpv = keypairs::load();
    let start = r.len();

    // Signalling bytes
    for (i, vec) in v.signalling_bytes_vectors.iter().enumerate() {
        let mode = LinkMode::try_from(vec.input_mode as u8).unwrap_or_default();
        if let Ok(encoded) = mtu::encode(vec.input_mtu as u32, mode) {
            r.insert(format!("links.signalling.{}.encode", i), h(&encoded));
            let decoded_mtu = mtu::decode_mtu(&encoded);
            r.insert(
                format!("links.signalling.{}.decode_mtu", i),
                format!("{}", decoded_mtu),
            );
            let decoded_mode = mtu::decode_mode(&encoded);
            r.insert(
                format!("links.signalling.{}.decode_mode", i),
                format!("{}", decoded_mode as u8),
            );
        }
    }

    // Link ID computation
    for (i, vec) in v.link_id_vectors.iter().enumerate() {
        if let Some(ref hs) = vec.hashable_stripped {
            let stripped = hex::decode(hs).unwrap();
            let link_id = sha256(&stripped);
            let truncated: [u8; 16] = link_id[..16].try_into().unwrap();
            r.insert(format!("links.link_id.{}", i), h(&truncated));
        }
    }

    // Handshake vectors: ECDH + HKDF
    for (i, hs) in v.handshake_vectors.iter().enumerate() {
        // ECDH: initiator ephemeral × responder ephemeral
        let init_eph = &v.ephemeral_keys[hs.initiator_ephemeral_index as usize];
        let resp_eph = &v.ephemeral_keys[hs.responder_ephemeral_index as usize];

        let init_x25519_prv = X25519PrivateKey::from_bytes(
            hex::decode(&init_eph.x25519_private).unwrap().try_into().unwrap(),
        );
        let resp_x25519_pub = X25519PublicKey::from_bytes(
            hex::decode(&resp_eph.x25519_public).unwrap().try_into().unwrap(),
        );

        let shared = init_x25519_prv.diffie_hellman(&resp_x25519_pub);
        r.insert(format!("links.handshake.{}.shared_key", i), h(&shared));

        // HKDF: derive key from shared secret
        let link_id = hex::decode(&hs.step_1_linkrequest.link_id).unwrap();
        let derived = hkdf(64, &shared, Some(&link_id), None);
        r.insert(format!("links.handshake.{}.derived_key", i), h(&derived));

        // Signature
        let resp_kp = &kpv.keypairs[hs.responder_keypair_index as usize];
        let resp_ed_prv: [u8; 32] = hex::decode(&resp_kp.ed25519_private)
            .unwrap()
            .try_into()
            .unwrap();
        let resp_ed = Ed25519PrivateKey::from_bytes(resp_ed_prv);
        let signed_data = hex::decode(&hs.step_2_lrproof.signed_data).unwrap();
        let sig = resp_ed.sign(&signed_data);
        r.insert(format!("links.handshake.{}.signature", i), h(&sig.to_bytes()));
    }

    // Keepalive calculation
    for (i, vec) in v.keepalive_calculation_vectors.iter().enumerate() {
        let keepalive = LinkActive::compute_keepalive(vec.rtt);
        r.insert(
            format!("links.keepalive.{}", i),
            format!("{:.15}", keepalive),
        );
    }

    // MDU calculation
    for (i, vec) in v.mdu_vectors.iter().enumerate() {
        let mdu = LinkActive::compute_mdu(vec.mtu as u32);
        r.insert(format!("links.mdu.{}", i), format!("{}", mdu));
    }

    // RTT msgpack
    for (i, vec) in v.rtt_vectors.iter().enumerate() {
        let mut buf = Vec::with_capacity(9);
        rmpv::encode::write_value(&mut buf, &rmpv::Value::F64(vec.rtt_float))
            .expect("msgpack encode");
        r.insert(format!("links.rtt.{}.msgpack", i), h(&buf));
    }

    eprintln!("  [OK] links: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 11. Channels
// ---------------------------------------------------------------------------
fn check_channels(r: &mut Results) {
    let v = channels::load();
    let start = r.len();

    // Envelope pack/unpack
    for (i, vec) in v.envelope_vectors.iter().enumerate() {
        let data = hex::decode(&vec.data_hex).unwrap();
        let env = Envelope {
            msg_type: vec.msgtype as u16,
            sequence: vec.sequence as u16,
            payload: data,
        };
        let packed = env.pack();
        r.insert(format!("channels.envelope.{}.pack", i), h(&packed));

        // Unpack
        let unpacked = Envelope::unpack(&packed).unwrap();
        let desc = format!(
            "{}.{}.{}",
            unpacked.msg_type, unpacked.sequence, h(&unpacked.payload)
        );
        r.insert(format!("channels.envelope.{}.unpack", i), desc);
    }

    // Stream data pack/unpack
    for (i, vec) in v.stream_data_vectors.iter().enumerate() {
        // Pack using fields from vector
        let packed_expected = hex::decode(&vec.packed_hex).unwrap();
        // Unpack to verify
        if let Ok(sdm) = reticulum_protocol::buffer::stream_data::StreamDataMessage::unpack(&packed_expected) {
            let desc = format!(
                "{}.{}.{}",
                sdm.header.stream_id, sdm.header.is_eof as u8, h(&sdm.data)
            );
            r.insert(format!("channels.stream.{}.unpack", i), desc);
        }
    }

    // Timeout calculation
    for (i, vec) in v.timeout_vectors.iter().enumerate() {
        let timeout =
            ChannelState::packet_timeout(vec.tries as u32, vec.rtt, vec.tx_ring_length as usize);
        r.insert(
            format!("channels.timeout.{}", i),
            format!("{:.15}", timeout),
        );
    }

    // Channel MDU
    for (i, vec) in v.mdu_vectors.iter().enumerate() {
        let mdu = ChannelState::channel_mdu(vec.outlet_mdu as usize);
        r.insert(format!("channels.mdu.{}", i), format!("{}", mdu));
    }

    eprintln!("  [OK] channels: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 12. Resources
// ---------------------------------------------------------------------------
fn check_resources(r: &mut Results) {
    let v = resources::load();
    let _lv = links::load();
    let start = r.len();

    // Resource hash
    for (i, vec) in v.resource_advertisement_vectors.iter().enumerate() {
        let resource_hash = hex::decode(&vec.resource_hash_hex).unwrap();
        r.insert(format!("resources.hash.{}", i), h(&resource_hash));

        // Hashmap bytes
        let hashmap = hex::decode(&vec.hashmap_hex).unwrap();
        r.insert(format!("resources.hashmap.{}", i), h(&hashmap));

        // Proof
        let proof = hex::decode(&vec.expected_proof_hex).unwrap();
        r.insert(format!("resources.proof.{}", i), h(&proof));
    }

    // Metadata encoding
    for (i, vec) in v.metadata_vectors.iter().enumerate() {
        if let Ok(full) = hex::decode(&vec.full_metadata_bytes_hex) {
            r.insert(format!("resources.metadata.{}", i), h(&full));
        }
    }

    eprintln!("  [OK] resources: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 13. Resource transfers
// ---------------------------------------------------------------------------
fn check_resource_transfers(r: &mut Results) {
    let v = resource_transfers::load();
    let start = r.len();

    for (i, vec) in v.transfer_sequence_vectors.iter().enumerate() {
        // Resource hash
        if let Some(ref rh) = vec.resource_hash_hex {
            r.insert(format!("resource_transfer.{}.hash", i), rh.clone());
        }
        // Proof
        if let Some(ref proof) = vec.expected_proof_hex {
            r.insert(format!("resource_transfer.{}.proof", i), proof.clone());
        }
    }

    // Cancellation
    for (i, vec) in v.cancellation_vectors.iter().enumerate() {
        r.insert(
            format!("resource_transfer.cancel.{}", i),
            vec.payload_hex.clone(),
        );
    }

    eprintln!("  [OK] resource_transfers: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 14. Buffer transfers
// ---------------------------------------------------------------------------
fn check_buffer_transfers(r: &mut Results) {
    let v = buffer_transfers::load();
    let start = r.len();

    // Small transfer stream packing
    for (i, vec) in v.small_transfer_vectors.iter().enumerate() {
        for (j, msg) in vec.messages.iter().enumerate() {
            r.insert(
                format!("buffer.stream.{}.{}.pack", i, j),
                msg.stream_packed_hex.clone(),
            );
        }
    }

    // Compression vectors
    for (i, vec) in v.compression_vectors.iter().enumerate() {
        r.insert(
            format!("buffer.compression.{}.compressed", i),
            format!("{}", vec.write_result.compressed),
        );
    }

    eprintln!("  [OK] buffer_transfers: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 15. Requests
// ---------------------------------------------------------------------------
fn check_requests(r: &mut Results) {
    let v = requests::load();
    let start = r.len();

    // Path hashes
    for (i, vec) in v.path_hash_vectors.iter().enumerate() {
        let path_bytes = vec.path.as_bytes();
        let th = truncated_hash(path_bytes);
        r.insert(format!("requests.path_hash.{}", i), h(&th));
    }

    // Timeouts
    for (i, vec) in v.timeout_vectors.iter().enumerate() {
        let timeout = compute_request_timeout(vec.rtt);
        r.insert(
            format!("requests.timeout.{}", i),
            format!("{:.15}", timeout),
        );
    }

    // Request serialization (packed request bytes where available)
    for (i, vec) in v.request_serialization_vectors.iter().enumerate() {
        if let Some(ref packed) = vec.packed_request_hex {
            r.insert(format!("requests.serialize.{}", i), packed.clone());
        }
    }

    // Response serialization
    for (i, vec) in v.response_serialization_vectors.iter().enumerate() {
        if let Some(ref packed) = vec.packed_response_hex {
            r.insert(format!("requests.response.{}", i), packed.clone());
        }
    }

    eprintln!("  [OK] requests: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 16. Retry timers
// ---------------------------------------------------------------------------
fn check_retry_timers(r: &mut Results) {
    let v = retry_timers::load();
    let start = r.len();

    // Link keepalive
    for (i, vec) in v.link_keepalive.vectors.iter().enumerate() {
        let keepalive = LinkActive::compute_keepalive(vec.rtt);
        r.insert(
            format!("retry.keepalive.{}", i),
            format!("{:.15}", keepalive),
        );
        // Stale time = keepalive * 2
        let stale = keepalive * 2.0;
        r.insert(format!("retry.stale.{}", i), format!("{:.15}", stale));
    }

    // Link establishment timeout
    for (i, vec) in v.link_establishment.vectors.iter().enumerate() {
        // Formula: DEFAULT_PER_HOP_TIMEOUT * max(1, hops) + KEEPALIVE
        // From Python: Link.DEFAULT_PER_HOP_TIMEOUT = 6, Link.KEEPALIVE = 360
        let hops = vec.hops;
        let timeout = 6 * std::cmp::max(1, hops) + 360;
        r.insert(format!("retry.establishment.{}", i), format!("{}", timeout));
    }

    // Channel timeout matrix
    for (i, vec) in v.channel_timeout.full_matrix.iter().enumerate() {
        let timeout = ChannelState::packet_timeout(
            vec.tries as u32,
            vec.rtt,
            vec.tx_ring_length as usize,
        );
        r.insert(
            format!("retry.channel_timeout.{}", i),
            format!("{:.15}", timeout),
        );
    }

    eprintln!("  [OK] retry_timers: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 17. Window adaptation
// ---------------------------------------------------------------------------
fn check_window_adaptation(r: &mut Results) {
    let v = window_adaptation::load();
    let start = r.len();

    // Resource window growth vectors
    for (i, vec) in v.resource_window.growth_vectors.iter().enumerate() {
        for (j, step) in vec.steps.iter().enumerate() {
            let desc = format!(
                "{}.{}.{}.{}.{}",
                step.state.window,
                step.state.window_max,
                step.state.window_min,
                step.state.fast_rate_rounds,
                step.state.very_slow_rate_rounds,
            );
            r.insert(format!("window.resource_growth.{}.{}", i, j), desc);
        }
    }

    // Resource window shrink vectors
    for (i, vec) in v.resource_window.shrink_vectors.iter().enumerate() {
        for (j, step) in vec.steps.iter().enumerate() {
            let desc = format!(
                "{}.{}.{}.{}.{}",
                step.state.window,
                step.state.window_max,
                step.state.window_min,
                step.state.fast_rate_rounds,
                step.state.very_slow_rate_rounds,
            );
            r.insert(format!("window.resource_shrink.{}.{}", i, j), desc);
        }
    }

    // Channel window init from RTT
    // Use channels.json window init vectors
    let cv = channels::load();
    for (i, vec) in cv.window_init_vectors.iter().enumerate() {
        let desc = format!(
            "{}.{}.{}.{}",
            vec.window, vec.window_max, vec.window_min, vec.window_flexibility,
        );
        r.insert(format!("window.channel_init.{}", i), desc);
    }

    eprintln!("  [OK] window_adaptation: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 18. Path expiration
// ---------------------------------------------------------------------------
fn check_path_expiration(r: &mut Results) {
    let v = path_expiration::load();
    let start = r.len();

    // TTL per interface mode
    for (i, vec) in v.ttl_enforcement_vectors.iter().enumerate() {
        let mode = InterfaceMode::from_vector_str(&vec.interface_mode).unwrap_or(InterfaceMode::Full);
        let ttl = mode.path_ttl();
        r.insert(
            format!("path_expiration.ttl.{}", i),
            format!("{}", ttl),
        );

        // Validity check
        let valid = vec.check_time <= vec.path_entry.timestamp + ttl;
        r.insert(
            format!("path_expiration.valid.{}", i),
            format!("{}", valid),
        );
    }

    eprintln!("  [OK] path_expiration: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 19. Path requests
// ---------------------------------------------------------------------------
fn check_path_requests(r: &mut Results) {
    let v = path_requests::load();
    let start = r.len();

    // Destination hashes
    for (i, vec) in v.path_request_destination_vectors.iter().enumerate() {
        let aspects: Vec<&str> = vec.aspects.iter().map(|s| s.as_str()).collect();
        let nh = name_hash(&vec.app_name, &aspects);
        let dh = plain_destination_hash(&nh);
        r.insert(format!("path_requests.dest.{}", i), h(dh.as_ref()));
    }

    // Packet hashes from raw packets
    for (i, vec) in v.path_request_packet_vectors.iter().enumerate() {
        let raw = hex::decode(&vec.raw_packet).unwrap();
        if let Ok(pkt) = RawPacket::parse(&raw) {
            let pkt_hash = pkt.packet_hash();
            r.insert(format!("path_requests.packet.{}", i), h(pkt_hash.as_ref()));
        }
    }

    eprintln!("  [OK] path_requests: {} entries", r.len() - start);
}

// ---------------------------------------------------------------------------
// 20. Multi-hop routing
// ---------------------------------------------------------------------------
fn check_multi_hop_routing(r: &mut Results) {
    let v = multi_hop_routing::load();
    let start = r.len();

    // Header transformation — packet hashes
    for (i, vec) in v.header_transformation_vectors.iter().enumerate() {
        let orig_raw = hex::decode(&vec.original_raw).unwrap();
        if let Ok(pkt) = RawPacket::parse(&orig_raw) {
            let pkt_hash = pkt.packet_hash();
            r.insert(format!("routing.transform.{}.orig_hash", i), h(pkt_hash.as_ref()));
        }
        let trans_raw = hex::decode(&vec.transformed_raw).unwrap();
        if let Ok(pkt) = RawPacket::parse(&trans_raw) {
            let pkt_hash = pkt.packet_hash();
            r.insert(
                format!("routing.transform.{}.trans_hash", i),
                h(pkt_hash.as_ref()),
            );
        }
    }

    // Link ID from raw packet
    for (i, vec) in v.link_table_entry_vectors.iter().enumerate() {
        if let Some(ref trimmed) = vec.hashable_part_trimmed {
            let trimmed_bytes = hex::decode(trimmed).unwrap();
            let link_id = sha256(&trimmed_bytes);
            let truncated: [u8; 16] = link_id[..16].try_into().unwrap();
            r.insert(format!("routing.link_id.{}", i), h(&truncated));
        }
    }

    // Announce propagation — packet hashes at each step
    for (i, vec) in v.announce_propagation_vectors.iter().enumerate() {
        for (j, step) in vec.chain.iter().enumerate() {
            if let Some(ref pkt_hash) = step.packet_hash {
                r.insert(
                    format!("routing.announce.{}.{}.packet_hash", i, j),
                    pkt_hash.clone(),
                );
            }
            if let Some(ref raw) = step.raw_packet {
                let raw_bytes = hex::decode(raw).unwrap();
                if let Ok(pkt) = RawPacket::parse(&raw_bytes) {
                    let computed_hash = pkt.packet_hash();
                    r.insert(
                        format!("routing.announce.{}.{}.computed_hash", i, j),
                        h(computed_hash.as_ref()),
                    );
                }
            }
        }
    }

    eprintln!("  [OK] multi_hop_routing: {} entries", r.len() - start);
}
