//! Pure, synchronous routing decision functions.
//!
//! These functions encapsulate the transport relay and forwarding logic
//! that was previously embedded in the async `Node` event loop. By
//! separating decision-making from I/O, every routing path can be tested
//! with fast, deterministic unit tests.

use reticulum_core::constants::{DestinationType, PacketType};
use reticulum_core::packet::context::ContextType;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::{DestinationHash, LinkId, TruncatedHash};
use reticulum_transport::path::PathTable;
use reticulum_transport::path::types::InterfaceId;
use reticulum_transport::router::dispatch::{
    compute_link_id_from_raw, inject_transport_header, strip_transport_header,
};
use reticulum_transport::router::tables::LinkTable;
use reticulum_transport::router::types::{LinkTableEntry, ReverseEntry};

/// An I/O action to execute after a routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportAction {
    /// Send data to a specific interface.
    TransmitTo {
        interface: InterfaceId,
        data: Vec<u8>,
    },
    /// Broadcast data to all interfaces except the excluded one.
    Broadcast {
        exclude: Option<InterfaceId>,
        data: Vec<u8>,
    },
    /// Drop the packet (no forwarding).
    Drop,
}

/// A mutation to apply to routing tables after a decision.
#[derive(Debug, Clone)]
pub enum TableMutation {
    /// Insert a new link table entry.
    InsertLinkTableEntry {
        link_id: LinkId,
        entry: LinkTableEntry,
    },
    /// Insert a new reverse table entry.
    InsertReverseTableEntry {
        key: TruncatedHash,
        entry: ReverseEntry,
    },
    /// Mark a link table entry as validated.
    ValidateLinkTableEntry { link_id: LinkId },
}

/// Decide how to forward a HEADER_1 packet after local handling.
pub fn decide_header1_forwarding(
    packet: &RawPacket,
    raw: &[u8],
    from_iface: InterfaceId,
    handled_locally: bool,
    enable_transport: bool,
    link_table: &LinkTable,
) -> (Vec<TransportAction>, Vec<TableMutation>) {
    if handled_locally {
        return (vec![], vec![]);
    }

    // Transport nodes must NOT flood announces as HEADER_1.
    // Announces propagate only via the retransmission mechanism with HEADER_2.
    if enable_transport && packet.flags.packet_type == PacketType::Announce {
        return (vec![TransportAction::Drop], vec![]);
    }

    // Route LRPROOF via link table when transport is enabled.
    if enable_transport
        && packet.flags.packet_type == PacketType::Proof
        && packet.context == ContextType::Lrproof
        && let Some((actions, mutations)) =
            route_lrproof_via_link_table(packet, raw, from_iface, link_table)
    {
        return (actions, mutations);
    }

    // Route link data via link table when transport is enabled.
    if enable_transport
        && packet.flags.destination_type == DestinationType::Link
        && packet.flags.packet_type != PacketType::LinkRequest
        && packet.context != ContextType::Lrproof
        && let Some((actions, mutations)) =
            route_link_data_via_link_table(packet, raw, from_iface, link_table)
    {
        return (actions, mutations);
    }

    // Default: flood to all other interfaces with hops incremented.
    let mut forward_packet = packet.clone();
    forward_packet.hops = packet.hops.saturating_add(1);
    let forward_raw = forward_packet.serialize();

    (
        vec![TransportAction::Broadcast {
            exclude: Some(from_iface),
            data: forward_raw,
        }],
        vec![],
    )
}

/// Route an LRPROOF via the link table (used by both HEADER_1 and HEADER_2 paths).
fn route_lrproof_via_link_table(
    packet: &RawPacket,
    raw: &[u8],
    from_iface: InterfaceId,
    link_table: &LinkTable,
) -> Option<(Vec<TransportAction>, Vec<TableMutation>)> {
    let link_id_bytes: [u8; 16] = packet.destination.as_ref().try_into().ok()?;
    let link_id = LinkId::new(link_id_bytes);

    let entry = link_table.get(&link_id)?;

    if from_iface != entry.next_hop_interface {
        return None;
    }

    let mut forwarded = raw.to_vec();
    forwarded[1] = packet.hops.saturating_add(1);

    Some((
        vec![TransportAction::TransmitTo {
            interface: entry.received_interface,
            data: forwarded,
        }],
        vec![TableMutation::ValidateLinkTableEntry { link_id }],
    ))
}

/// Route link data bidirectionally via the link table.
fn route_link_data_via_link_table(
    packet: &RawPacket,
    raw: &[u8],
    from_iface: InterfaceId,
    link_table: &LinkTable,
) -> Option<(Vec<TransportAction>, Vec<TableMutation>)> {
    let link_id_bytes: [u8; 16] = packet.destination.as_ref().try_into().ok()?;
    let link_id = LinkId::new(link_id_bytes);

    let entry = link_table.get(&link_id)?;

    let target_iface = if from_iface == entry.next_hop_interface {
        entry.received_interface
    } else if from_iface == entry.received_interface {
        entry.next_hop_interface
    } else {
        return None;
    };

    let mut forwarded = raw.to_vec();
    forwarded[1] = packet.hops.saturating_add(1);

    Some((
        vec![TransportAction::TransmitTo {
            interface: target_iface,
            data: forwarded,
        }],
        vec![],
    ))
}

/// Decide how to relay a HEADER_2 packet addressed to us.
pub fn decide_transport_relay(
    packet: &RawPacket,
    raw: &[u8],
    from_iface: InterfaceId,
    path_table: &PathTable,
    link_table: &LinkTable,
    now_secs: u64,
) -> (Vec<TransportAction>, Vec<TableMutation>) {
    let new_hops = packet.hops.saturating_add(1);

    // LRPROOF: route via link table back to initiator.
    if packet.flags.packet_type == PacketType::Proof && packet.context == ContextType::Lrproof {
        return decide_relay_lrproof(packet, raw, from_iface, link_table, new_hops);
    }

    // Link data (not LINKREQUEST): route bidirectionally via link table.
    if packet.flags.destination_type == DestinationType::Link
        && packet.flags.packet_type != PacketType::LinkRequest
    {
        return decide_relay_link_packet(packet, raw, from_iface, link_table, new_hops);
    }

    // All other packets (including LINKREQUEST): use path table.
    let path_info = path_table
        .get(&packet.destination)
        .map(|e| (e.next_hop, e.hops, e.receiving_interface));

    let (next_hop, remaining_hops, outbound_iface) = match path_info {
        Some(info) => info,
        None => return (vec![TransportAction::Drop], vec![]),
    };

    let mut mutations = Vec::new();

    // For LINKREQUEST: create link table entry.
    if packet.flags.packet_type == PacketType::LinkRequest {
        if let Ok(link_id) = compute_link_id_from_raw(raw) {
            let proof_timeout = now_secs + 30 * (remaining_hops.max(1) as u64);
            let entry = LinkTableEntry {
                timestamp: now_secs,
                next_hop_transport_id: next_hop,
                next_hop_interface: outbound_iface,
                remaining_hops,
                received_interface: from_iface,
                taken_hops: new_hops,
                dest_hash: packet.destination,
                validated: false,
                proof_timeout,
            };
            mutations.push(TableMutation::InsertLinkTableEntry { link_id, entry });
        }
    } else {
        // For non-link-request packets: create reverse table entry.
        let packet_hash = packet.packet_hash();
        let trunc = packet_hash.truncated();
        mutations.push(TableMutation::InsertReverseTableEntry {
            key: trunc,
            entry: ReverseEntry {
                receiving_interface: from_iface,
                outbound_interface: outbound_iface,
                timestamp: now_secs,
            },
        });
    }

    // Forward based on remaining hops.
    // Our hops are 1 less than Python's since we don't increment on reception,
    // so remaining_hops <= 1 corresponds to Python's remaining_hops <= 1.
    let action = if remaining_hops > 1 {
        // Keep HEADER_2, replace transport_id with next_hop.
        let mut forwarded = raw.to_vec();
        forwarded[1] = new_hops;
        forwarded[2..18].copy_from_slice(next_hop.as_ref());
        TransportAction::TransmitTo {
            interface: outbound_iface,
            data: forwarded,
        }
    } else {
        // Final hop: strip HEADER_2 → HEADER_1.
        match strip_transport_header(raw, new_hops) {
            Ok(stripped) => TransportAction::TransmitTo {
                interface: outbound_iface,
                data: stripped,
            },
            Err(_) => TransportAction::Drop,
        }
    };

    (vec![action], mutations)
}

/// Relay an LRPROOF via the link table.
fn decide_relay_lrproof(
    packet: &RawPacket,
    raw: &[u8],
    from_iface: InterfaceId,
    link_table: &LinkTable,
    new_hops: u8,
) -> (Vec<TransportAction>, Vec<TableMutation>) {
    let link_id_bytes: [u8; 16] = match packet.destination.as_ref().try_into() {
        Ok(b) => b,
        Err(_) => return (vec![TransportAction::Drop], vec![]),
    };
    let link_id = LinkId::new(link_id_bytes);

    let entry = match link_table.get(&link_id) {
        Some(e) => e,
        None => return (vec![TransportAction::Drop], vec![]),
    };

    if from_iface != entry.next_hop_interface {
        return (vec![TransportAction::Drop], vec![]);
    }

    let mut forwarded = raw.to_vec();
    forwarded[1] = new_hops;

    (
        vec![TransportAction::TransmitTo {
            interface: entry.received_interface,
            data: forwarded,
        }],
        vec![TableMutation::ValidateLinkTableEntry { link_id }],
    )
}

/// Relay a link-related packet bidirectionally via the link table.
fn decide_relay_link_packet(
    packet: &RawPacket,
    raw: &[u8],
    from_iface: InterfaceId,
    link_table: &LinkTable,
    new_hops: u8,
) -> (Vec<TransportAction>, Vec<TableMutation>) {
    let link_id_bytes: [u8; 16] = match packet.destination.as_ref().try_into() {
        Ok(b) => b,
        Err(_) => return (vec![TransportAction::Drop], vec![]),
    };
    let link_id = LinkId::new(link_id_bytes);

    let entry = match link_table.get(&link_id) {
        Some(e) => e,
        None => return (vec![TransportAction::Drop], vec![]),
    };

    let target_iface = if from_iface == entry.received_interface {
        entry.next_hop_interface
    } else if from_iface == entry.next_hop_interface {
        entry.received_interface
    } else {
        return (vec![TransportAction::Drop], vec![]);
    };

    let mut forwarded = raw.to_vec();
    forwarded[1] = new_hops;

    (
        vec![TransportAction::TransmitTo {
            interface: target_iface,
            data: forwarded,
        }],
        vec![],
    )
}

/// Prepare an announce for retransmission as a transport node.
pub fn prepare_announce_retransmission(
    raw: &[u8],
    enable_transport: bool,
    our_identity_hash: Option<&TruncatedHash>,
) -> Option<Vec<u8>> {
    if !enable_transport {
        return Some(raw.to_vec());
    }

    let our_hash = our_identity_hash?;

    // Increment hops before injection.
    let mut raw_inc = raw.to_vec();
    if raw_inc.len() > 1 {
        raw_inc[1] = raw_inc[1].saturating_add(1);
    }

    inject_transport_header(&raw_inc, our_hash).ok()
}

/// Decide how to send a link request based on path table information.
pub fn prepare_link_request_for_transport(
    lr_raw: &[u8],
    path_table: &PathTable,
    dest_hash: &DestinationHash,
) -> TransportAction {
    let path_info = path_table
        .get(dest_hash)
        .map(|e| (e.hops, e.next_hop, e.receiving_interface));

    if let Some((hops, next_hop, outbound_iface)) = path_info
        && hops > 0
        && next_hop.as_ref() != [0u8; 16]
        && let Ok(h2_raw) = inject_transport_header(lr_raw, &next_hop)
    {
        return TransportAction::TransmitTo {
            interface: outbound_iface,
            data: h2_raw,
        };
    }

    TransportAction::Broadcast {
        exclude: None,
        data: lr_raw.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::{HeaderType, TransportType};
    use reticulum_core::packet::flags::PacketFlags;
    use reticulum_core::types::PacketHash;
    use reticulum_transport::path::types::{InterfaceMode, PathEntry};

    // === Test helpers ===

    fn make_header1_announce(dest: DestinationHash, hops: u8) -> (RawPacket, Vec<u8>) {
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
            },
            hops,
            transport_id: None,
            destination: dest,
            context: ContextType::None,
            data: vec![0xAA; 20],
        };
        let raw = packet.serialize();
        (packet, raw)
    }

    fn make_header1_lrproof(link_id: LinkId, hops: u8) -> (RawPacket, Vec<u8>) {
        let bytes: [u8; 16] = link_id.as_ref().try_into().unwrap();
        let dest = DestinationHash::new(bytes);
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: true,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
            },
            hops,
            transport_id: None,
            destination: dest,
            context: ContextType::Lrproof,
            data: vec![0xBB; 64],
        };
        let raw = packet.serialize();
        (packet, raw)
    }

    fn make_header1_link_data(link_id: LinkId, hops: u8) -> (RawPacket, Vec<u8>) {
        let bytes: [u8; 16] = link_id.as_ref().try_into().unwrap();
        let dest = DestinationHash::new(bytes);
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
            },
            hops,
            transport_id: None,
            destination: dest,
            context: ContextType::None,
            data: vec![0xCC; 48],
        };
        let raw = packet.serialize();
        (packet, raw)
    }

    fn make_header1_data(dest: DestinationHash, hops: u8) -> (RawPacket, Vec<u8>) {
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops,
            transport_id: None,
            destination: dest,
            context: ContextType::None,
            data: vec![0xDD; 10],
        };
        let raw = packet.serialize();
        (packet, raw)
    }

    fn make_header2_data(
        transport_id: DestinationHash,
        dest: DestinationHash,
        hops: u8,
    ) -> (RawPacket, Vec<u8>) {
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header2,
                context_flag: false,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops,
            transport_id: Some(transport_id),
            destination: dest,
            context: ContextType::None,
            data: vec![0xEE; 10],
        };
        let raw = packet.serialize();
        (packet, raw)
    }

    fn make_header2_linkrequest(
        transport_id: DestinationHash,
        dest: DestinationHash,
        hops: u8,
    ) -> (RawPacket, Vec<u8>) {
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header2,
                context_flag: false,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
            },
            hops,
            transport_id: Some(transport_id),
            destination: dest,
            context: ContextType::None,
            // LINKREQUEST data: ephemeral X25519(32) + ephemeral Ed25519(32) + signalling(3) = 67
            data: vec![0xFF; 67],
        };
        let raw = packet.serialize();
        (packet, raw)
    }

    fn make_header2_lrproof(
        transport_id: DestinationHash,
        link_id: LinkId,
        hops: u8,
    ) -> (RawPacket, Vec<u8>) {
        let bytes: [u8; 16] = link_id.as_ref().try_into().unwrap();
        let dest = DestinationHash::new(bytes);
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header2,
                context_flag: true,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
            },
            hops,
            transport_id: Some(transport_id),
            destination: dest,
            context: ContextType::Lrproof,
            data: vec![0xBB; 64],
        };
        let raw = packet.serialize();
        (packet, raw)
    }

    fn make_header2_link_data(
        transport_id: DestinationHash,
        link_id: LinkId,
        hops: u8,
    ) -> (RawPacket, Vec<u8>) {
        let bytes: [u8; 16] = link_id.as_ref().try_into().unwrap();
        let dest = DestinationHash::new(bytes);
        let packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header2,
                context_flag: false,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
            },
            hops,
            transport_id: Some(transport_id),
            destination: dest,
            context: ContextType::None,
            data: vec![0xCC; 48],
        };
        let raw = packet.serialize();
        (packet, raw)
    }

    fn make_link_table_entry(
        next_hop_iface: InterfaceId,
        recv_iface: InterfaceId,
        rem_hops: u8,
    ) -> LinkTableEntry {
        LinkTableEntry {
            timestamp: 1000,
            next_hop_transport_id: TruncatedHash::new([0xAA; 16]),
            next_hop_interface: next_hop_iface,
            remaining_hops: rem_hops,
            received_interface: recv_iface,
            taken_hops: 1,
            dest_hash: DestinationHash::new([0xBB; 16]),
            validated: false,
            proof_timeout: 2000,
        }
    }

    fn make_path_entry(hops: u8, next_hop: TruncatedHash, iface: InterfaceId) -> PathEntry {
        PathEntry::new(
            1000,
            next_hop,
            hops,
            InterfaceMode::Full,
            vec![],
            iface,
            PacketHash::new([0; 32]),
        )
    }

    // === Transport announce flooding ===

    #[test]
    fn transport_node_does_not_flood_announce() {
        let dest = DestinationHash::new([0x11; 16]);
        let (packet, raw) = make_header1_announce(dest, 0);
        let link_table = LinkTable::new();

        let (actions, _) = decide_header1_forwarding(
            &packet,
            &raw,
            InterfaceId(1),
            false,
            true, // transport enabled
            &link_table,
        );

        assert_eq!(actions, vec![TransportAction::Drop]);
    }

    #[test]
    fn non_transport_node_floods_announce() {
        let dest = DestinationHash::new([0x11; 16]);
        let (packet, raw) = make_header1_announce(dest, 0);
        let link_table = LinkTable::new();

        let (actions, _) = decide_header1_forwarding(
            &packet,
            &raw,
            InterfaceId(1),
            false,
            false, // transport disabled
            &link_table,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::Broadcast { exclude, data } => {
                assert_eq!(*exclude, Some(InterfaceId(1)));
                let forwarded = RawPacket::parse(data).unwrap();
                assert_eq!(forwarded.hops, 1);
            }
            other => panic!("expected Broadcast, got: {other:?}"),
        }
    }

    #[test]
    fn transport_node_floods_non_announce_data() {
        let dest = DestinationHash::new([0x22; 16]);
        let (packet, raw) = make_header1_data(dest, 0);
        let link_table = LinkTable::new();

        let (actions, _) = decide_header1_forwarding(
            &packet,
            &raw,
            InterfaceId(1),
            false,
            true, // transport enabled
            &link_table,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::Broadcast { exclude, .. } => {
                assert_eq!(*exclude, Some(InterfaceId(1)));
            }
            other => panic!("expected Broadcast, got: {other:?}"),
        }
    }

    // === Remaining hops strip ===

    #[test]
    fn remaining_hops_0_strips_to_header1() {
        let transport_id = DestinationHash::new([0xAA; 16]);
        let dest = DestinationHash::new([0xBB; 16]);
        let (packet, raw) = make_header2_data(transport_id, dest, 2);

        let mut path_table = PathTable::new();
        let next_hop = TruncatedHash::new([0xCC; 16]);
        path_table.insert(dest, make_path_entry(0, next_hop, InterfaceId(5)));

        let link_table = LinkTable::new();

        let (actions, _) = decide_transport_relay(
            &packet,
            &raw,
            InterfaceId(1),
            &path_table,
            &link_table,
            1000,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::TransmitTo { data, .. } => {
                let output = RawPacket::parse(data).unwrap();
                assert_eq!(output.flags.header_type, HeaderType::Header1);
            }
            other => panic!("expected TransmitTo, got: {other:?}"),
        }
    }

    #[test]
    fn remaining_hops_1_strips_to_header1() {
        let transport_id = DestinationHash::new([0xAA; 16]);
        let dest = DestinationHash::new([0xBB; 16]);
        let (packet, raw) = make_header2_data(transport_id, dest, 2);

        let mut path_table = PathTable::new();
        let next_hop = TruncatedHash::new([0xCC; 16]);
        path_table.insert(dest, make_path_entry(1, next_hop, InterfaceId(5)));

        let link_table = LinkTable::new();

        let (actions, _) = decide_transport_relay(
            &packet,
            &raw,
            InterfaceId(1),
            &path_table,
            &link_table,
            1000,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::TransmitTo { data, .. } => {
                let output = RawPacket::parse(data).unwrap();
                assert_eq!(output.flags.header_type, HeaderType::Header1);
            }
            other => panic!("expected TransmitTo, got: {other:?}"),
        }
    }

    #[test]
    fn remaining_hops_2_keeps_header2() {
        let transport_id = DestinationHash::new([0xAA; 16]);
        let dest = DestinationHash::new([0xBB; 16]);
        let (packet, raw) = make_header2_data(transport_id, dest, 2);

        let mut path_table = PathTable::new();
        let next_hop = TruncatedHash::new([0xCC; 16]);
        path_table.insert(dest, make_path_entry(2, next_hop, InterfaceId(5)));

        let link_table = LinkTable::new();

        let (actions, _) = decide_transport_relay(
            &packet,
            &raw,
            InterfaceId(1),
            &path_table,
            &link_table,
            1000,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::TransmitTo { data, .. } => {
                let output = RawPacket::parse(data).unwrap();
                assert_eq!(output.flags.header_type, HeaderType::Header2);
                assert_eq!(output.transport_id.unwrap().as_ref(), &[0xCC; 16]);
            }
            other => panic!("expected TransmitTo, got: {other:?}"),
        }
    }

    #[test]
    fn remaining_hops_0_output_is_valid_packet() {
        let transport_id = DestinationHash::new([0xAA; 16]);
        let dest = DestinationHash::new([0xBB; 16]);
        let (packet, raw) = make_header2_data(transport_id, dest, 2);

        let mut path_table = PathTable::new();
        let next_hop = TruncatedHash::new([0xCC; 16]);
        path_table.insert(dest, make_path_entry(0, next_hop, InterfaceId(5)));

        let link_table = LinkTable::new();

        let (actions, _) = decide_transport_relay(
            &packet,
            &raw,
            InterfaceId(1),
            &path_table,
            &link_table,
            1000,
        );

        match &actions[0] {
            TransportAction::TransmitTo { data, .. } => {
                // Must parse successfully
                let output = RawPacket::parse(data).unwrap();
                assert_eq!(output.destination, dest);
            }
            other => panic!("expected TransmitTo, got: {other:?}"),
        }
    }

    // === Announce retransmission hops ===

    #[test]
    fn retx_increments_hops_before_injection() {
        let dest = DestinationHash::new([0x11; 16]);
        let (_, raw) = make_header1_announce(dest, 0);
        let our_hash = TruncatedHash::new([0xAA; 16]);

        let result = prepare_announce_retransmission(&raw, true, Some(&our_hash));
        let h2_raw = result.expect("should produce HEADER_2");
        let output = RawPacket::parse(&h2_raw).unwrap();

        assert_eq!(output.flags.header_type, HeaderType::Header2);
        assert_eq!(output.hops, 1); // was 0, incremented to 1
    }

    #[test]
    fn retx_preserves_raw_when_non_transport() {
        let dest = DestinationHash::new([0x11; 16]);
        let (_, raw) = make_header1_announce(dest, 2);

        let result = prepare_announce_retransmission(&raw, false, None);
        assert_eq!(result.unwrap(), raw);
    }

    #[test]
    fn retx_transport_id_is_our_hash() {
        let dest = DestinationHash::new([0x11; 16]);
        let (_, raw) = make_header1_announce(dest, 0);
        let our_hash = TruncatedHash::new([0xAA; 16]);

        let result = prepare_announce_retransmission(&raw, true, Some(&our_hash));
        let h2_raw = result.unwrap();
        let output = RawPacket::parse(&h2_raw).unwrap();

        assert_eq!(output.transport_id.unwrap().as_ref(), &[0xAA; 16]);
    }

    #[test]
    fn retx_hops_saturate_at_255() {
        let dest = DestinationHash::new([0x11; 16]);
        let (_, raw) = make_header1_announce(dest, 255);
        let our_hash = TruncatedHash::new([0xAA; 16]);

        let result = prepare_announce_retransmission(&raw, true, Some(&our_hash));
        let h2_raw = result.unwrap();
        let output = RawPacket::parse(&h2_raw).unwrap();

        assert_eq!(output.hops, 255); // saturating_add prevents overflow
    }

    // === H1 link table routing ===

    #[test]
    fn h1_lrproof_routed_via_link_table() {
        let link_id = LinkId::new([0x11; 16]);
        let (packet, raw) = make_header1_lrproof(link_id, 0);

        let next_hop_iface = InterfaceId(2);
        let recv_iface = InterfaceId(3);

        let mut link_table = LinkTable::new();
        link_table.insert(
            link_id,
            make_link_table_entry(next_hop_iface, recv_iface, 2),
        );

        let (actions, mutations) = decide_header1_forwarding(
            &packet,
            &raw,
            next_hop_iface, // from == next_hop_iface
            false,
            true,
            &link_table,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::TransmitTo { interface, .. } => {
                assert_eq!(*interface, recv_iface);
            }
            other => panic!("expected TransmitTo, got: {other:?}"),
        }
        assert!(
            mutations
                .iter()
                .any(|m| matches!(m, TableMutation::ValidateLinkTableEntry { .. }))
        );
    }

    #[test]
    fn h1_lrproof_wrong_interface_falls_through() {
        let link_id = LinkId::new([0x11; 16]);
        let (packet, raw) = make_header1_lrproof(link_id, 0);

        let next_hop_iface = InterfaceId(2);
        let recv_iface = InterfaceId(3);

        let mut link_table = LinkTable::new();
        link_table.insert(
            link_id,
            make_link_table_entry(next_hop_iface, recv_iface, 2),
        );

        let (actions, _) = decide_header1_forwarding(
            &packet,
            &raw,
            InterfaceId(99), // from != next_hop_iface
            false,
            true,
            &link_table,
        );

        // Falls through to broadcast
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], TransportAction::Broadcast { .. }));
    }

    #[test]
    fn h1_lrproof_no_link_entry_floods() {
        let link_id = LinkId::new([0x11; 16]);
        let (packet, raw) = make_header1_lrproof(link_id, 0);

        let link_table = LinkTable::new(); // empty

        let (actions, _) =
            decide_header1_forwarding(&packet, &raw, InterfaceId(1), false, true, &link_table);

        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], TransportAction::Broadcast { .. }));
    }

    #[test]
    fn h1_lrproof_validates_link_entry() {
        let link_id = LinkId::new([0x11; 16]);
        let (packet, raw) = make_header1_lrproof(link_id, 0);

        let next_hop_iface = InterfaceId(2);
        let recv_iface = InterfaceId(3);

        let mut link_table = LinkTable::new();
        link_table.insert(
            link_id,
            make_link_table_entry(next_hop_iface, recv_iface, 2),
        );

        let (_, mutations) =
            decide_header1_forwarding(&packet, &raw, next_hop_iface, false, true, &link_table);

        assert!(mutations.iter().any(
            |m| matches!(m, TableMutation::ValidateLinkTableEntry { link_id: lid } if *lid == link_id)
        ));
    }

    #[test]
    fn h1_link_data_forward_direction() {
        let link_id = LinkId::new([0x22; 16]);
        let (packet, raw) = make_header1_link_data(link_id, 0);

        let next_hop_iface = InterfaceId(2);
        let recv_iface = InterfaceId(3);

        let mut link_table = LinkTable::new();
        link_table.insert(
            link_id,
            make_link_table_entry(next_hop_iface, recv_iface, 2),
        );

        let (actions, _) = decide_header1_forwarding(
            &packet,
            &raw,
            recv_iface, // from == recv_iface → forward to next_hop_iface
            false,
            true,
            &link_table,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::TransmitTo { interface, .. } => {
                assert_eq!(*interface, next_hop_iface);
            }
            other => panic!("expected TransmitTo, got: {other:?}"),
        }
    }

    #[test]
    fn h1_link_data_reverse_direction() {
        let link_id = LinkId::new([0x22; 16]);
        let (packet, raw) = make_header1_link_data(link_id, 0);

        let next_hop_iface = InterfaceId(2);
        let recv_iface = InterfaceId(3);

        let mut link_table = LinkTable::new();
        link_table.insert(
            link_id,
            make_link_table_entry(next_hop_iface, recv_iface, 2),
        );

        let (actions, _) = decide_header1_forwarding(
            &packet,
            &raw,
            next_hop_iface, // from == next_hop_iface → forward to recv_iface
            false,
            true,
            &link_table,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::TransmitTo { interface, .. } => {
                assert_eq!(*interface, recv_iface);
            }
            other => panic!("expected TransmitTo, got: {other:?}"),
        }
    }

    #[test]
    fn h1_link_data_unknown_interface_floods() {
        let link_id = LinkId::new([0x22; 16]);
        let (packet, raw) = make_header1_link_data(link_id, 0);

        let next_hop_iface = InterfaceId(2);
        let recv_iface = InterfaceId(3);

        let mut link_table = LinkTable::new();
        link_table.insert(
            link_id,
            make_link_table_entry(next_hop_iface, recv_iface, 2),
        );

        let (actions, _) = decide_header1_forwarding(
            &packet,
            &raw,
            InterfaceId(99), // neither next_hop nor recv
            false,
            true,
            &link_table,
        );

        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], TransportAction::Broadcast { .. }));
    }

    // === Transport relay correctness ===

    #[test]
    fn relay_linkrequest_creates_link_table_entry() {
        let transport_id = DestinationHash::new([0xAA; 16]);
        let dest = DestinationHash::new([0xBB; 16]);
        let (packet, raw) = make_header2_linkrequest(transport_id, dest, 1);

        let mut path_table = PathTable::new();
        let next_hop = TruncatedHash::new([0xCC; 16]);
        path_table.insert(dest, make_path_entry(2, next_hop, InterfaceId(5)));

        let link_table = LinkTable::new();

        let (_, mutations) = decide_transport_relay(
            &packet,
            &raw,
            InterfaceId(1),
            &path_table,
            &link_table,
            1000,
        );

        assert!(
            mutations
                .iter()
                .any(|m| matches!(m, TableMutation::InsertLinkTableEntry { .. }))
        );
    }

    #[test]
    fn relay_non_link_creates_reverse_entry() {
        let transport_id = DestinationHash::new([0xAA; 16]);
        let dest = DestinationHash::new([0xBB; 16]);
        let (packet, raw) = make_header2_data(transport_id, dest, 1);

        let mut path_table = PathTable::new();
        let next_hop = TruncatedHash::new([0xCC; 16]);
        path_table.insert(dest, make_path_entry(2, next_hop, InterfaceId(5)));

        let link_table = LinkTable::new();

        let (_, mutations) = decide_transport_relay(
            &packet,
            &raw,
            InterfaceId(1),
            &path_table,
            &link_table,
            1000,
        );

        assert!(
            mutations
                .iter()
                .any(|m| matches!(m, TableMutation::InsertReverseTableEntry { .. }))
        );
    }

    #[test]
    fn relay_no_path_drops() {
        let transport_id = DestinationHash::new([0xAA; 16]);
        let dest = DestinationHash::new([0xBB; 16]);
        let (packet, raw) = make_header2_data(transport_id, dest, 1);

        let path_table = PathTable::new(); // empty
        let link_table = LinkTable::new();

        let (actions, _) = decide_transport_relay(
            &packet,
            &raw,
            InterfaceId(1),
            &path_table,
            &link_table,
            1000,
        );

        assert_eq!(actions, vec![TransportAction::Drop]);
    }

    #[test]
    fn relay_lrproof_via_link_table() {
        let link_id = LinkId::new([0x11; 16]);
        let transport_id = DestinationHash::new([0xAA; 16]);
        let (packet, raw) = make_header2_lrproof(transport_id, link_id, 1);

        let next_hop_iface = InterfaceId(2);
        let recv_iface = InterfaceId(3);

        let mut link_table = LinkTable::new();
        link_table.insert(
            link_id,
            make_link_table_entry(next_hop_iface, recv_iface, 2),
        );

        let path_table = PathTable::new();

        let (actions, mutations) = decide_transport_relay(
            &packet,
            &raw,
            next_hop_iface, // proof arrives on next_hop side
            &path_table,
            &link_table,
            1000,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::TransmitTo { interface, .. } => {
                assert_eq!(*interface, recv_iface);
            }
            other => panic!("expected TransmitTo, got: {other:?}"),
        }
        assert!(
            mutations
                .iter()
                .any(|m| matches!(m, TableMutation::ValidateLinkTableEntry { .. }))
        );
    }

    #[test]
    fn relay_link_data_bidirectional() {
        let link_id = LinkId::new([0x22; 16]);
        let transport_id = DestinationHash::new([0xAA; 16]);

        let next_hop_iface = InterfaceId(2);
        let recv_iface = InterfaceId(3);

        let mut link_table = LinkTable::new();
        link_table.insert(
            link_id,
            make_link_table_entry(next_hop_iface, recv_iface, 2),
        );

        let path_table = PathTable::new();

        // Forward direction: from recv → next_hop
        let (packet1, raw1) = make_header2_link_data(transport_id, link_id, 1);
        let (actions1, _) =
            decide_transport_relay(&packet1, &raw1, recv_iface, &path_table, &link_table, 1000);
        match &actions1[0] {
            TransportAction::TransmitTo { interface, .. } => {
                assert_eq!(*interface, next_hop_iface);
            }
            other => panic!("expected TransmitTo for forward, got: {other:?}"),
        }

        // Reverse direction: from next_hop → recv
        let (packet2, raw2) = make_header2_link_data(transport_id, link_id, 1);
        let (actions2, _) = decide_transport_relay(
            &packet2,
            &raw2,
            next_hop_iface,
            &path_table,
            &link_table,
            1000,
        );
        match &actions2[0] {
            TransportAction::TransmitTo { interface, .. } => {
                assert_eq!(*interface, recv_iface);
            }
            other => panic!("expected TransmitTo for reverse, got: {other:?}"),
        }
    }

    #[test]
    fn link_request_multi_hop_injects_h2() {
        let dest = DestinationHash::new([0xBB; 16]);
        // Build a HEADER_1 link request for prepare_link_request_for_transport
        let lr_packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
            },
            hops: 0,
            transport_id: None,
            destination: dest,
            context: ContextType::None,
            data: vec![0xFF; 67],
        };
        let lr_raw = lr_packet.serialize();

        let mut path_table = PathTable::new();
        let next_hop = TruncatedHash::new([0xCC; 16]);
        path_table.insert(dest, make_path_entry(2, next_hop, InterfaceId(5)));

        let action = prepare_link_request_for_transport(&lr_raw, &path_table, &dest);

        match action {
            TransportAction::TransmitTo { interface, data } => {
                assert_eq!(interface, InterfaceId(5));
                let output = RawPacket::parse(&data).unwrap();
                assert_eq!(output.flags.header_type, HeaderType::Header2);
            }
            other => panic!("expected TransmitTo, got: {other:?}"),
        }
    }

    #[test]
    fn link_request_direct_broadcasts() {
        let dest = DestinationHash::new([0xBB; 16]);
        let lr_packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
            },
            hops: 0,
            transport_id: None,
            destination: dest,
            context: ContextType::None,
            data: vec![0xFF; 67],
        };
        let lr_raw = lr_packet.serialize();

        let mut path_table = PathTable::new();
        let next_hop = TruncatedHash::new([0x00; 16]); // zero = direct
        path_table.insert(dest, make_path_entry(0, next_hop, InterfaceId(5)));

        let action = prepare_link_request_for_transport(&lr_raw, &path_table, &dest);
        assert!(matches!(action, TransportAction::Broadcast { .. }));
    }

    #[test]
    fn link_request_no_path_broadcasts() {
        let dest = DestinationHash::new([0xBB; 16]);
        let lr_packet = RawPacket {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
            },
            hops: 0,
            transport_id: None,
            destination: dest,
            context: ContextType::None,
            data: vec![0xFF; 67],
        };
        let lr_raw = lr_packet.serialize();

        let path_table = PathTable::new(); // empty

        let action = prepare_link_request_for_transport(&lr_raw, &path_table, &dest);
        assert!(matches!(action, TransportAction::Broadcast { .. }));
    }

    #[test]
    fn handled_locally_no_forwarding() {
        let dest = DestinationHash::new([0x11; 16]);
        let (packet, raw) = make_header1_data(dest, 0);
        let link_table = LinkTable::new();

        let (actions, mutations) = decide_header1_forwarding(
            &packet,
            &raw,
            InterfaceId(1),
            true, // handled locally
            true,
            &link_table,
        );

        assert!(actions.is_empty());
        assert!(mutations.is_empty());
    }
}
