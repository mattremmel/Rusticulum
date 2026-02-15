//! Announce packet cache for PATH_RESPONSE serving.
//!
//! Caches raw announce packets so transport nodes can serve them in response
//! to path requests. Entries are keyed by the packet hash from the path table.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use reticulum_core::types::PacketHash;

/// A cached announce packet.
#[derive(Debug, Clone)]
pub struct CachedAnnounce {
    /// The raw announce packet bytes.
    pub raw_packet: Vec<u8>,
}

/// In-memory announce cache with optional disk persistence.
pub struct AnnounceCache {
    memory: HashMap<PacketHash, CachedAnnounce>,
    cache_dir: Option<PathBuf>,
}

impl AnnounceCache {
    /// Create a new announce cache.
    ///
    /// If `cache_dir` is `Some`, announces will be persisted to disk.
    pub fn new(cache_dir: Option<PathBuf>) -> Self {
        Self {
            memory: HashMap::new(),
            cache_dir,
        }
    }

    /// Insert a cached announce.
    pub fn insert(&mut self, packet_hash: PacketHash, raw_packet: Vec<u8>) {
        self.memory.insert(
            packet_hash,
            CachedAnnounce {
                raw_packet,
            },
        );
    }

    /// Get a cached announce by packet hash.
    #[must_use]
    pub fn get(&self, packet_hash: &PacketHash) -> Option<&CachedAnnounce> {
        self.memory.get(packet_hash)
    }

    /// Remove cache entries not in the active set.
    ///
    /// Returns the number of entries removed.
    pub fn clean(&mut self, active_hashes: &HashSet<PacketHash>) -> usize {
        let before = self.memory.len();
        self.memory.retain(|hash, _| active_hashes.contains(hash));
        before - self.memory.len()
    }

    /// Number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.memory.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memory.is_empty()
    }

    /// Persist all cached announces to disk.
    ///
    /// Each announce is written as raw bytes to `{cache_dir}/{hex(packet_hash)}`.
    pub async fn persist(&self) -> Result<(), std::io::Error> {
        let dir = match &self.cache_dir {
            Some(d) => d,
            None => return Ok(()),
        };

        tokio::fs::create_dir_all(dir).await?;

        for (hash, cached) in &self.memory {
            let filename = hex::encode(hash.as_ref());
            let path = dir.join(&filename);
            tokio::fs::write(&path, &cached.raw_packet).await?;
        }

        // Remove files not in the current cache
        Self::remove_stale_files(dir, &self.memory).await?;

        Ok(())
    }

    /// Load cached announces from disk.
    pub async fn load_from_disk(&mut self) -> Result<usize, std::io::Error> {
        let dir = match &self.cache_dir {
            Some(d) => d.clone(),
            None => return Ok(0),
        };

        if !dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        let mut entries = tokio::fs::read_dir(&dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let filename = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Parse packet hash from filename
            let hash_bytes = match hex::decode(&filename) {
                Ok(b) if b.len() == 32 => b,
                _ => continue,
            };
            let hash_arr: [u8; 32] = hash_bytes.try_into().expect("len checked above");
            let packet_hash = PacketHash::new(hash_arr);

            match tokio::fs::read(&path).await {
                Ok(raw_packet) if !raw_packet.is_empty() => {
                    self.memory.insert(
                        packet_hash,
                        CachedAnnounce { raw_packet },
                    );
                    count += 1;
                }
                _ => continue,
            }
        }

        Ok(count)
    }

    /// Remove disk files not present in the current memory cache.
    async fn remove_stale_files(
        dir: &Path,
        memory: &HashMap<PacketHash, CachedAnnounce>,
    ) -> Result<(), std::io::Error> {
        let known: HashSet<String> = memory
            .keys()
            .map(|h| hex::encode(h.as_ref()))
            .collect();

        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && !known.contains(name)
            {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(seed: u8) -> PacketHash {
        PacketHash::new([seed; 32])
    }

    #[test]
    fn insert_and_get_roundtrip() {
        let mut cache = AnnounceCache::new(None);
        let hash = make_hash(1);
        let data = vec![0x01, 0x02, 0x03];

        cache.insert(hash, data.clone());
        let cached = cache.get(&hash).unwrap();
        assert_eq!(cached.raw_packet, data);
    }

    #[test]
    fn get_missing_returns_none() {
        let cache = AnnounceCache::new(None);
        assert!(cache.get(&make_hash(1)).is_none());
    }

    #[test]
    fn clean_removes_stale_keeps_active() {
        let mut cache = AnnounceCache::new(None);
        let active_hash = make_hash(1);
        let stale_hash = make_hash(2);

        cache.insert(active_hash, vec![0x01]);
        cache.insert(stale_hash, vec![0x02]);
        assert_eq!(cache.len(), 2);

        let mut active = HashSet::new();
        active.insert(active_hash);

        let removed = cache.clean(&active);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&active_hash).is_some());
        assert!(cache.get(&stale_hash).is_none());
    }

    #[test]
    fn clean_with_empty_active_removes_all() {
        let mut cache = AnnounceCache::new(None);
        cache.insert(make_hash(1), vec![0x01]);
        cache.insert(make_hash(2), vec![0x02]);

        let removed = cache.clean(&HashSet::new());
        assert_eq!(removed, 2);
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn disk_persist_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("announces");

        let mut cache = AnnounceCache::new(Some(cache_dir.clone()));
        cache.insert(make_hash(0xAA), vec![0x10, 0x20, 0x30]);
        cache.insert(make_hash(0xBB), vec![0x40, 0x50]);

        cache.persist().await.unwrap();

        // Load into a new cache
        let mut loaded = AnnounceCache::new(Some(cache_dir));
        let count = loaded.load_from_disk().await.unwrap();
        assert_eq!(count, 2);

        let aa = loaded.get(&make_hash(0xAA)).unwrap();
        assert_eq!(aa.raw_packet, vec![0x10, 0x20, 0x30]);

        let bb = loaded.get(&make_hash(0xBB)).unwrap();
        assert_eq!(bb.raw_packet, vec![0x40, 0x50]);
    }

    #[tokio::test]
    async fn load_from_nonexistent_dir_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("nonexistent");

        let mut cache = AnnounceCache::new(Some(cache_dir));
        let count = cache.load_from_disk().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn persist_cleans_stale_files() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("announces");

        // Create initial cache with 2 entries
        let mut cache = AnnounceCache::new(Some(cache_dir.clone()));
        cache.insert(make_hash(1), vec![0x01]);
        cache.insert(make_hash(2), vec![0x02]);
        cache.persist().await.unwrap();

        // Remove one entry and persist again
        let mut active = HashSet::new();
        active.insert(make_hash(1));
        cache.clean(&active);
        cache.persist().await.unwrap();

        // Load and verify only 1 entry remains
        let mut loaded = AnnounceCache::new(Some(cache_dir));
        let count = loaded.load_from_disk().await.unwrap();
        assert_eq!(count, 1);
        assert!(loaded.get(&make_hash(1)).is_some());
        assert!(loaded.get(&make_hash(2)).is_none());
    }
}
