//! Identity and state persistence for Reticulum nodes.
//!
//! Persists the transport identity (raw 64-byte key file), path table, and
//! packet deduplication hashlist across restarts. Uses atomic writes (write to
//! `.tmp`, then rename) to prevent corruption.

use std::path::{Path, PathBuf};

use tokio::fs;

use reticulum_core::identity::Identity;
use reticulum_transport::dedup::PacketHashlist;
use reticulum_transport::path::table::PathTable;

use crate::storage_codec;

/// File name for the 64-byte raw transport identity.
const IDENTITY_FILE: &str = "transport_identity";

/// File name for the serialized path table.
const PATH_TABLE_FILE: &str = "destination_table";

/// File name for the serialized packet hashlist.
const HASHLIST_FILE: &str = "packet_hashlist";

/// Errors from storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialize(String),

    #[error("deserialization error: {0}")]
    Deserialize(String),

    #[error("invalid identity length: expected 64, got {0}")]
    InvalidIdentityLength(usize),

    #[error("failed to determine storage directory: {0}")]
    Directory(String),
}

/// Persistent storage for node state.
pub struct Storage {
    base_dir: PathBuf,
}

impl Storage {
    /// Create a new storage instance, creating the directory if needed.
    pub fn new(base_dir: PathBuf) -> Result<Self, StorageError> {
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Create storage at the default path (`~/.reticulum/storage`).
    pub fn default_path() -> Result<Self, StorageError> {
        let home = dirs::home_dir()
            .ok_or_else(|| StorageError::Directory("could not determine home directory".into()))?;
        Self::new(home.join(".reticulum").join("storage"))
    }

    /// Save a transport identity as raw 64 bytes.
    pub async fn save_identity(&self, identity: &Identity) -> Result<(), StorageError> {
        let bytes = identity
            .private_key_bytes()
            .ok_or(StorageError::InvalidIdentityLength(0))?;
        let path = self.base_dir.join(IDENTITY_FILE);
        self.atomic_write(&path, &bytes).await?;

        // Set file permissions to 0600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
        }

        Ok(())
    }

    /// Load a transport identity. Returns `Ok(None)` if the file doesn't exist.
    pub async fn load_identity(&self) -> Result<Option<Identity>, StorageError> {
        let path = self.base_dir.join(IDENTITY_FILE);
        match fs::read(&path).await {
            Ok(bytes) => {
                if bytes.len() != 64 {
                    return Err(StorageError::InvalidIdentityLength(bytes.len()));
                }
                let arr: [u8; 64] = bytes.try_into().unwrap();
                Ok(Some(Identity::from_private_bytes(&arr)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Save the path table.
    pub async fn save_path_table(&self, table: &PathTable) -> Result<(), StorageError> {
        let bytes = storage_codec::serialize_path_table(table)
            .map_err(|e| StorageError::Serialize(e.to_string()))?;

        self.atomic_write(&self.base_dir.join(PATH_TABLE_FILE), &bytes)
            .await
    }

    /// Load the path table. Returns an empty table if the file doesn't exist.
    pub async fn load_path_table(&self) -> Result<PathTable, StorageError> {
        let path = self.base_dir.join(PATH_TABLE_FILE);
        match fs::read(&path).await {
            Ok(bytes) => storage_codec::deserialize_path_table(&bytes)
                .map_err(|e| StorageError::Deserialize(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PathTable::new()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Save the packet hashlist.
    pub async fn save_hashlist(&self, hashlist: &PacketHashlist) -> Result<(), StorageError> {
        let bytes = storage_codec::serialize_hashlist(hashlist)
            .map_err(|e| StorageError::Serialize(e.to_string()))?;

        self.atomic_write(&self.base_dir.join(HASHLIST_FILE), &bytes)
            .await
    }

    /// Load the packet hashlist. Returns an empty hashlist if the file doesn't exist.
    pub async fn load_hashlist(&self) -> Result<PacketHashlist, StorageError> {
        let path = self.base_dir.join(HASHLIST_FILE);
        match fs::read(&path).await {
            Ok(bytes) => storage_codec::deserialize_hashlist(&bytes)
                .map_err(|e| StorageError::Deserialize(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PacketHashlist::new()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Write data atomically: write to a `.tmp` file then rename.
    async fn atomic_write(&self, path: &Path, data: &[u8]) -> Result<(), StorageError> {
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, data).await?;
        fs::rename(&tmp_path, path).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_codec::MAX_PERSISTED_BLOBS;
    use reticulum_core::types::{DestinationHash, PacketHash, TruncatedHash};
    use reticulum_transport::path::types::{InterfaceId, InterfaceMode, PathEntry};

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

    #[tokio::test]
    async fn test_identity_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_path_buf()).unwrap();

        let identity = Identity::generate();
        storage.save_identity(&identity).await.unwrap();

        let loaded = storage.load_identity().await.unwrap().expect("should load");
        assert_eq!(identity.hash().as_ref(), loaded.hash().as_ref());
        assert_eq!(identity.public_key_bytes(), loaded.public_key_bytes());
    }

    #[tokio::test]
    async fn test_identity_load_missing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_path_buf()).unwrap();

        let result = storage.load_identity().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_identity_load_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_path_buf()).unwrap();

        // Write garbage bytes (wrong length)
        std::fs::write(dir.path().join(IDENTITY_FILE), b"too short").unwrap();

        let result = storage.load_identity().await;
        assert!(result.is_err());
        match result {
            Err(StorageError::InvalidIdentityLength(9)) => {}
            Err(other) => panic!("expected InvalidIdentityLength(9), got: {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_path_table_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_path_buf()).unwrap();

        let mut table = PathTable::new();
        let entry1 = make_entry(1000, 3, vec![[0x11; 10], [0x22; 10]]);
        let entry2 = make_entry(2000, 5, vec![[0x33; 10]]);
        table.insert(make_dest(1), entry1);
        table.insert(make_dest(2), entry2);

        storage.save_path_table(&table).await.unwrap();
        let loaded = storage.load_path_table().await.unwrap();

        assert_eq!(loaded.len(), 2);
        let e1 = loaded.get(&make_dest(1)).unwrap();
        assert_eq!(e1.timestamp, 1000);
        assert_eq!(e1.hops, 3);
        assert_eq!(e1.random_blobs.len(), 2);

        let e2 = loaded.get(&make_dest(2)).unwrap();
        assert_eq!(e2.timestamp, 2000);
        assert_eq!(e2.hops, 5);
    }

    #[tokio::test]
    async fn test_path_table_empty_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_path_buf()).unwrap();

        let table = PathTable::new();
        storage.save_path_table(&table).await.unwrap();
        let loaded = storage.load_path_table().await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn test_path_table_random_blob_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_path_buf()).unwrap();

        // Create entry with 64 blobs
        let blobs: Vec<[u8; 10]> = (0u8..64).map(|i| [i; 10]).collect();
        let entry = PathEntry {
            timestamp: 1000,
            next_hop: make_next_hop(1),
            hops: 1,
            expires: 1000 + 604800,
            random_blobs: blobs,
            receiving_interface: InterfaceId(1),
            packet_hash: make_packet_hash(1),
            unresponsive: false,
        };
        assert_eq!(entry.random_blobs.len(), 64);

        let mut table = PathTable::new();
        table.insert(make_dest(1), entry);

        storage.save_path_table(&table).await.unwrap();
        let loaded = storage.load_path_table().await.unwrap();
        let e = loaded.get(&make_dest(1)).unwrap();
        assert_eq!(e.random_blobs.len(), MAX_PERSISTED_BLOBS);
    }

    #[tokio::test]
    async fn test_hashlist_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_path_buf()).unwrap();

        let mut hashlist = PacketHashlist::new();
        let h1 = PacketHash::new([0x11; 32]);
        let h2 = PacketHash::new([0x22; 32]);
        hashlist.insert(h1);
        hashlist.insert(h2);

        storage.save_hashlist(&hashlist).await.unwrap();
        let loaded = storage.load_hashlist().await.unwrap();

        assert!(loaded.contains(&h1));
        assert!(loaded.contains(&h2));
        assert_eq!(loaded.len(), 2);
    }

    #[tokio::test]
    async fn test_hashlist_empty_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_path_buf()).unwrap();

        let hashlist = PacketHashlist::new();
        storage.save_hashlist(&hashlist).await.unwrap();
        let loaded = storage.load_hashlist().await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn test_atomic_write_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_path_buf()).unwrap();

        let path = dir.path().join("test_file");
        storage.atomic_write(&path, b"hello").await.unwrap();

        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn test_storage_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");

        assert!(!nested.exists());
        let _storage = Storage::new(nested.clone()).unwrap();
        assert!(nested.exists());
    }
}
