//! Pure serialization/deserialization for node state.
//!
//! Extracts the data-transformation logic from [`crate::storage`] so that
//! path-table and hashlist codecs can be tested without async I/O or temp dirs.

use serde::{Deserialize, Serialize};

use reticulum_core::types::{DestinationHash, PacketHash, TruncatedHash};
use reticulum_transport::dedup::PacketHashlist;
use reticulum_transport::path::table::PathTable;
use reticulum_transport::path::types::{InterfaceId, PathEntry};

use crate::link_manager::KnownDestinationEntry;

/// Maximum number of random blobs to persist per path entry.
pub const MAX_PERSISTED_BLOBS: usize = 32;

/// Errors from pure codec operations (no I/O variants).
#[derive(Debug, thiserror::Error)]
pub enum StorageCodecError {
    #[error("serialization error: {0}")]
    Serialize(String),

    #[error("deserialization error: {0}")]
    Deserialize(String),
}

/// Intermediate representation of a [`PathEntry`] for serialization.
#[derive(Debug, Serialize, Deserialize)]
pub struct StorablePathEntry {
    pub dest_hash: [u8; 16],
    pub timestamp: u64,
    pub next_hop: [u8; 16],
    pub hops: u8,
    pub expires: u64,
    pub random_blobs: Vec<[u8; 10]>,
    pub receiving_interface: u64,
    pub packet_hash: [u8; 32],
    pub unresponsive: bool,
}

/// Convert a destination hash + path entry into a storable form.
///
/// Truncates random blobs to [`MAX_PERSISTED_BLOBS`].
#[must_use]
pub fn path_entry_to_storable(dest: &DestinationHash, entry: &PathEntry) -> StorablePathEntry {
    let mut blobs = entry.random_blobs_to_vec();
    blobs.truncate(MAX_PERSISTED_BLOBS);

    let mut dest_hash = [0u8; 16];
    dest_hash.copy_from_slice(dest.as_ref());
    let mut next_hop = [0u8; 16];
    next_hop.copy_from_slice(entry.next_hop.as_ref());
    let mut packet_hash = [0u8; 32];
    packet_hash.copy_from_slice(entry.packet_hash.as_ref());

    StorablePathEntry {
        dest_hash,
        timestamp: entry.timestamp,
        next_hop,
        hops: entry.hops,
        expires: entry.expires,
        random_blobs: blobs,
        receiving_interface: entry.receiving_interface.0,
        packet_hash,
        unresponsive: entry.unresponsive,
    }
}

/// Convert a storable entry back into a (DestinationHash, PathEntry) pair.
pub fn storable_to_path_entry(storable: StorablePathEntry) -> (DestinationHash, PathEntry) {
    let dest = DestinationHash::new(storable.dest_hash);
    let entry = PathEntry::from_raw(
        storable.timestamp,
        TruncatedHash::new(storable.next_hop),
        storable.hops,
        storable.expires,
        storable.random_blobs,
        InterfaceId(storable.receiving_interface),
        PacketHash::new(storable.packet_hash),
        storable.unresponsive,
    );
    (dest, entry)
}

/// Serialize a [`PathTable`] to bytes via postcard.
pub fn serialize_path_table(table: &PathTable) -> Result<Vec<u8>, StorageCodecError> {
    let entries: Vec<StorablePathEntry> = table
        .iter()
        .map(|(dest, entry)| path_entry_to_storable(dest, entry))
        .collect();

    postcard::to_allocvec(&entries).map_err(|e| StorageCodecError::Serialize(e.to_string()))
}

/// Deserialize a [`PathTable`] from postcard-encoded bytes.
pub fn deserialize_path_table(bytes: &[u8]) -> Result<PathTable, StorageCodecError> {
    let entries: Vec<StorablePathEntry> =
        postcard::from_bytes(bytes).map_err(|e| StorageCodecError::Deserialize(e.to_string()))?;
    Ok(PathTable::from_entries(
        entries.into_iter().map(storable_to_path_entry),
    ))
}

/// Serialize a [`PacketHashlist`] to bytes via postcard.
pub fn serialize_hashlist(hashlist: &PacketHashlist) -> Result<Vec<u8>, StorageCodecError> {
    let hashes: Vec<[u8; 32]> = hashlist
        .iter_all()
        .map(|h| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h.as_ref());
            arr
        })
        .collect();

    postcard::to_allocvec(&hashes).map_err(|e| StorageCodecError::Serialize(e.to_string()))
}

/// Deserialize a [`PacketHashlist`] from postcard-encoded bytes.
pub fn deserialize_hashlist(bytes: &[u8]) -> Result<PacketHashlist, StorageCodecError> {
    let hashes: Vec<[u8; 32]> =
        postcard::from_bytes(bytes).map_err(|e| StorageCodecError::Deserialize(e.to_string()))?;
    Ok(PacketHashlist::from_hashes(
        hashes.into_iter().map(PacketHash::new),
    ))
}

/// Intermediate representation of a [`KnownDestinationEntry`] for serialization.
///
/// Uses `Vec<u8>` for the 64-byte public key since serde doesn't derive
/// for `[u8; 64]` out of the box.
#[derive(Debug, Serialize, Deserialize)]
pub struct StorableKnownDestination {
    pub dest_hash: [u8; 16],
    pub timestamp: f64,
    pub packet_hash: [u8; 32],
    pub public_key: Vec<u8>,
    pub app_data: Option<Vec<u8>>,
}

/// Convert a destination hash + known destination entry into storable form.
#[must_use]
pub fn known_dest_to_storable(
    dest: &DestinationHash,
    entry: &KnownDestinationEntry,
) -> StorableKnownDestination {
    let mut dest_hash = [0u8; 16];
    dest_hash.copy_from_slice(dest.as_ref());
    let mut packet_hash = [0u8; 32];
    packet_hash.copy_from_slice(entry.packet_hash.as_ref());

    StorableKnownDestination {
        dest_hash,
        timestamp: entry.timestamp,
        packet_hash,
        public_key: entry.public_key.to_vec(),
        app_data: entry.app_data.clone(),
    }
}

/// Convert a storable entry back into a (DestinationHash, KnownDestinationEntry) pair.
pub fn storable_to_known_dest(
    storable: StorableKnownDestination,
) -> (DestinationHash, KnownDestinationEntry) {
    let dest = DestinationHash::new(storable.dest_hash);
    let mut public_key = [0u8; 64];
    let len = storable.public_key.len().min(64);
    public_key[..len].copy_from_slice(&storable.public_key[..len]);
    let entry = KnownDestinationEntry {
        timestamp: storable.timestamp,
        packet_hash: PacketHash::new(storable.packet_hash),
        public_key,
        app_data: storable.app_data,
    };
    (dest, entry)
}

/// Serialize a known destinations map to bytes via postcard.
pub fn serialize_known_destinations(
    map: &std::collections::HashMap<DestinationHash, KnownDestinationEntry>,
) -> Result<Vec<u8>, StorageCodecError> {
    let entries: Vec<StorableKnownDestination> = map
        .iter()
        .map(|(dest, entry)| known_dest_to_storable(dest, entry))
        .collect();

    postcard::to_allocvec(&entries).map_err(|e| StorageCodecError::Serialize(e.to_string()))
}

/// Deserialize known destinations from postcard-encoded bytes.
pub fn deserialize_known_destinations(
    bytes: &[u8],
) -> Result<Vec<(DestinationHash, KnownDestinationEntry)>, StorageCodecError> {
    let entries: Vec<StorableKnownDestination> =
        postcard::from_bytes(bytes).map_err(|e| StorageCodecError::Deserialize(e.to_string()))?;
    Ok(entries.into_iter().map(storable_to_known_dest).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_transport::path::types::InterfaceMode;

    fn make_dest(seed: u8) -> DestinationHash {
        DestinationHash::new([seed; 16])
    }

    fn make_next_hop(seed: u8) -> TruncatedHash {
        TruncatedHash::new([seed; 16])
    }

    fn make_packet_hash(seed: u8) -> PacketHash {
        PacketHash::new([seed; 32])
    }

    fn make_entry(timestamp: u64, hops: u8, blobs: Vec<[u8; 10]>) -> PathEntry {
        PathEntry::new(
            timestamp,
            make_next_hop(0xAA),
            hops,
            InterfaceMode::Full,
            blobs,
            InterfaceId(42),
            make_packet_hash(0xBB),
        )
    }

    // --- path_entry_to_storable ---

    #[test]
    fn path_entry_to_storable_basic() {
        let dest = make_dest(0x11);
        let entry = make_entry(1000, 3, vec![[0x22; 10], [0x33; 10]]);
        let storable = path_entry_to_storable(&dest, &entry);

        assert_eq!(storable.dest_hash, [0x11; 16]);
        assert_eq!(storable.timestamp, 1000);
        assert_eq!(storable.hops, 3);
        assert_eq!(storable.random_blobs.len(), 2);
        assert_eq!(storable.receiving_interface, 42);
        assert_eq!(storable.packet_hash, [0xBB; 32]);
        assert!(!storable.unresponsive);
    }

    #[test]
    fn path_entry_to_storable_truncates_blobs() {
        let dest = make_dest(1);
        let blobs: Vec<[u8; 10]> = (0u8..64).map(|i| [i; 10]).collect();
        let entry = PathEntry::from_raw(
            1000,
            make_next_hop(1),
            1,
            1000 + 604800,
            blobs,
            InterfaceId(1),
            make_packet_hash(1),
            false,
        );

        let storable = path_entry_to_storable(&dest, &entry);
        assert_eq!(storable.random_blobs.len(), MAX_PERSISTED_BLOBS);
        // First blob preserved
        assert_eq!(storable.random_blobs[0], [0; 10]);
        // Last preserved blob
        assert_eq!(storable.random_blobs[31], [31; 10]);
    }

    #[test]
    fn path_entry_to_storable_empty_blobs() {
        let dest = make_dest(1);
        let entry = make_entry(500, 0, vec![]);
        let storable = path_entry_to_storable(&dest, &entry);
        assert!(storable.random_blobs.is_empty());
    }

    #[test]
    fn storable_to_path_entry_roundtrip() {
        let dest = make_dest(0x42);
        let entry = make_entry(9999, 7, vec![[0xAA; 10], [0xBB; 10], [0xCC; 10]]);
        let storable = path_entry_to_storable(&dest, &entry);
        let (rt_dest, rt_entry) = storable_to_path_entry(storable);

        assert_eq!(rt_dest.as_ref(), dest.as_ref());
        assert_eq!(rt_entry.timestamp, entry.timestamp);
        assert_eq!(rt_entry.hops, entry.hops);
        assert_eq!(rt_entry.expires, entry.expires);
        assert_eq!(rt_entry.random_blobs_to_vec(), entry.random_blobs_to_vec());
        assert_eq!(rt_entry.receiving_interface.0, entry.receiving_interface.0);
        assert_eq!(rt_entry.packet_hash.as_ref(), entry.packet_hash.as_ref());
        assert_eq!(rt_entry.unresponsive, entry.unresponsive);
    }

    // --- serialize/deserialize path table ---

    #[test]
    fn serialize_path_table_roundtrip() {
        let mut table = PathTable::new();
        table.insert(make_dest(1), make_entry(1000, 3, vec![[0x11; 10]]));
        table.insert(make_dest(2), make_entry(2000, 5, vec![[0x22; 10]]));
        table.insert(make_dest(3), make_entry(3000, 1, vec![]));

        let bytes = serialize_path_table(&table).unwrap();
        let loaded = deserialize_path_table(&bytes).unwrap();

        assert_eq!(loaded.len(), 3);
        assert!(loaded.get(&make_dest(1)).is_some());
        assert!(loaded.get(&make_dest(2)).is_some());
        assert!(loaded.get(&make_dest(3)).is_some());
    }

    #[test]
    fn serialize_path_table_empty() {
        let table = PathTable::new();
        let bytes = serialize_path_table(&table).unwrap();
        let loaded = deserialize_path_table(&bytes).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn serialize_path_table_single_entry() {
        let mut table = PathTable::new();
        table.insert(make_dest(0xFF), make_entry(42, 1, vec![[0x99; 10]]));

        let bytes = serialize_path_table(&table).unwrap();
        let loaded = deserialize_path_table(&bytes).unwrap();

        assert_eq!(loaded.len(), 1);
        let e = loaded.get(&make_dest(0xFF)).unwrap();
        assert_eq!(e.timestamp, 42);
        assert_eq!(e.hops, 1);
    }

    #[test]
    fn serialize_path_table_preserves_all_fields() {
        let mut table = PathTable::new();
        let entry = PathEntry::from_raw(
            123456,
            make_next_hop(0xDE),
            12,
            999999,
            vec![[0x01; 10], [0x02; 10]],
            InterfaceId(77),
            make_packet_hash(0xFE),
            true,
        );
        table.insert(make_dest(0xAB), entry);

        let bytes = serialize_path_table(&table).unwrap();
        let loaded = deserialize_path_table(&bytes).unwrap();

        let e = loaded.get(&make_dest(0xAB)).unwrap();
        assert_eq!(e.timestamp, 123456);
        assert_eq!(e.next_hop.as_ref(), &[0xDE; 16]);
        assert_eq!(e.hops, 12);
        assert_eq!(e.expires, 999999);
        assert_eq!(e.random_blobs_to_vec(), vec![[0x01; 10], [0x02; 10]]);
        assert_eq!(e.receiving_interface.0, 77);
        assert_eq!(e.packet_hash.as_ref(), &[0xFE; 32]);
        assert!(e.unresponsive);
    }

    #[test]
    fn serialize_path_table_blob_truncation() {
        let mut table = PathTable::new();
        let blobs: Vec<[u8; 10]> = (0u8..64).map(|i| [i; 10]).collect();
        let entry = PathEntry::from_raw(
            1000,
            make_next_hop(1),
            1,
            1000 + 604800,
            blobs,
            InterfaceId(1),
            make_packet_hash(1),
            false,
        );
        table.insert(make_dest(1), entry);

        let bytes = serialize_path_table(&table).unwrap();
        let loaded = deserialize_path_table(&bytes).unwrap();
        let e = loaded.get(&make_dest(1)).unwrap();
        assert_eq!(e.random_blobs().len(), MAX_PERSISTED_BLOBS);
    }

    #[test]
    fn deserialize_path_table_corrupt_bytes() {
        let result = deserialize_path_table(b"this is not valid postcard");
        assert!(
            matches!(result, Err(StorageCodecError::Deserialize(_))),
            "expected Deserialize error"
        );
    }

    #[test]
    fn deserialize_path_table_empty_bytes() {
        // An empty slice should decode as an empty vec (postcard encodes empty vec as a single 0 length byte)
        // but a truly empty slice is invalid postcard
        let result = deserialize_path_table(&[]);
        // postcard needs at least a length prefix; empty slice is an error
        assert!(result.is_err());
    }

    // --- serialize/deserialize hashlist ---

    #[test]
    fn serialize_hashlist_roundtrip() {
        let mut hashlist = PacketHashlist::new();
        hashlist.insert(PacketHash::new([0x11; 32]));
        hashlist.insert(PacketHash::new([0x22; 32]));
        hashlist.insert(PacketHash::new([0x33; 32]));

        let bytes = serialize_hashlist(&hashlist).unwrap();
        let loaded = deserialize_hashlist(&bytes).unwrap();

        assert!(loaded.contains(&PacketHash::new([0x11; 32])));
        assert!(loaded.contains(&PacketHash::new([0x22; 32])));
        assert!(loaded.contains(&PacketHash::new([0x33; 32])));
    }

    #[test]
    fn serialize_hashlist_empty() {
        let hashlist = PacketHashlist::new();
        let bytes = serialize_hashlist(&hashlist).unwrap();
        let loaded = deserialize_hashlist(&bytes).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn serialize_hashlist_single() {
        let mut hashlist = PacketHashlist::new();
        hashlist.insert(PacketHash::new([0xFF; 32]));

        let bytes = serialize_hashlist(&hashlist).unwrap();
        let loaded = deserialize_hashlist(&bytes).unwrap();

        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains(&PacketHash::new([0xFF; 32])));
    }

    #[test]
    fn deserialize_hashlist_contains() {
        let mut hashlist = PacketHashlist::new();
        let h1 = PacketHash::new([0xAA; 32]);
        let h2 = PacketHash::new([0xBB; 32]);
        let h3 = PacketHash::new([0xCC; 32]);
        hashlist.insert(h1);
        hashlist.insert(h2);

        let bytes = serialize_hashlist(&hashlist).unwrap();
        let loaded = deserialize_hashlist(&bytes).unwrap();

        assert!(loaded.contains(&h1));
        assert!(loaded.contains(&h2));
        assert!(!loaded.contains(&h3));
    }

    #[test]
    fn deserialize_hashlist_corrupt_bytes() {
        let result = deserialize_hashlist(b"garbage data here!!!");
        assert!(
            matches!(result, Err(StorageCodecError::Deserialize(_))),
            "expected Deserialize error"
        );
    }

    #[test]
    fn serialize_hashlist_large() {
        let mut hashlist = PacketHashlist::new();
        for i in 0u8..150 {
            let mut arr = [0u8; 32];
            arr[0] = i;
            arr[1] = i.wrapping_mul(7);
            hashlist.insert(PacketHash::new(arr));
        }

        let bytes = serialize_hashlist(&hashlist).unwrap();
        let loaded = deserialize_hashlist(&bytes).unwrap();

        // Verify all 150 hashes survived
        for i in 0u8..150 {
            let mut arr = [0u8; 32];
            arr[0] = i;
            arr[1] = i.wrapping_mul(7);
            assert!(loaded.contains(&PacketHash::new(arr)), "missing hash {i}");
        }
    }

    #[test]
    fn deserialize_hashlist_empty_bytes() {
        let result = deserialize_hashlist(&[]);
        // postcard needs at least a length prefix; empty slice is an error
        assert!(result.is_err());
    }

    // --- serialize/deserialize known destinations ---

    fn make_known_dest(seed: u8, app_data: Option<Vec<u8>>) -> KnownDestinationEntry {
        KnownDestinationEntry {
            timestamp: 1000.0 + seed as f64,
            packet_hash: make_packet_hash(seed),
            public_key: [seed; 64],
            app_data,
        }
    }

    #[test]
    fn known_dest_to_storable_roundtrip() {
        let dest = make_dest(0x42);
        let entry = make_known_dest(0x42, Some(b"hello".to_vec()));
        let storable = known_dest_to_storable(&dest, &entry);
        let (rt_dest, rt_entry) = storable_to_known_dest(storable);

        assert_eq!(rt_dest.as_ref(), dest.as_ref());
        assert!((rt_entry.timestamp - entry.timestamp).abs() < f64::EPSILON);
        assert_eq!(rt_entry.packet_hash.as_ref(), entry.packet_hash.as_ref());
        assert_eq!(rt_entry.public_key, entry.public_key);
        assert_eq!(rt_entry.app_data, entry.app_data);
    }

    #[test]
    fn known_dest_roundtrip_no_app_data() {
        let dest = make_dest(0x11);
        let entry = make_known_dest(0x11, None);
        let storable = known_dest_to_storable(&dest, &entry);
        let (rt_dest, rt_entry) = storable_to_known_dest(storable);

        assert_eq!(rt_dest.as_ref(), dest.as_ref());
        assert!(rt_entry.app_data.is_none());
    }

    #[test]
    fn serialize_known_destinations_roundtrip() {
        let mut map = std::collections::HashMap::new();
        map.insert(make_dest(1), make_known_dest(1, Some(b"data1".to_vec())));
        map.insert(make_dest(2), make_known_dest(2, None));
        map.insert(make_dest(3), make_known_dest(3, Some(b"data3".to_vec())));

        let bytes = serialize_known_destinations(&map).unwrap();
        let loaded = deserialize_known_destinations(&bytes).unwrap();

        assert_eq!(loaded.len(), 3);
        for (dest, entry) in &loaded {
            let original = map.get(dest).expect("dest should be in original map");
            assert!((entry.timestamp - original.timestamp).abs() < f64::EPSILON);
            assert_eq!(entry.public_key, original.public_key);
            assert_eq!(entry.app_data, original.app_data);
        }
    }

    #[test]
    fn serialize_known_destinations_empty() {
        let map = std::collections::HashMap::new();
        let bytes = serialize_known_destinations(&map).unwrap();
        let loaded = deserialize_known_destinations(&bytes).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn deserialize_known_destinations_corrupt() {
        let result = deserialize_known_destinations(b"not valid postcard bytes");
        assert!(matches!(result, Err(StorageCodecError::Deserialize(_))));
    }
}
