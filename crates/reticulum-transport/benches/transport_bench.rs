use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use reticulum_core::types::{DestinationHash, PacketHash, TruncatedHash};
use reticulum_transport::dedup::PacketHashlist;
use reticulum_transport::ifac::{IfacConfig, IfacCredentials, ifac_apply, ifac_verify};
use reticulum_transport::path::table::PathTable;
use reticulum_transport::path::types::{InterfaceId, InterfaceMode, PathEntry};

fn make_dest_hash(i: u32) -> DestinationHash {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&i.to_be_bytes());
    DestinationHash::new(bytes)
}

fn make_packet_hash(i: u32) -> PacketHash {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&i.to_be_bytes());
    PacketHash::new(bytes)
}

fn make_path_entry() -> PathEntry {
    PathEntry::new(
        1_000_000,
        TruncatedHash::new([0xBB; 16]),
        2,
        InterfaceMode::Full,
        vec![],
        InterfaceId(1),
        PacketHash::new([0xCC; 32]),
    )
}

fn populate_hashlist(list: &mut PacketHashlist, count: u32) {
    for i in 0..count {
        list.insert(make_packet_hash(i));
    }
}

fn populate_path_table(table: &mut PathTable, count: u32) {
    for i in 0..count {
        table.insert(make_dest_hash(i), make_path_entry());
    }
}

fn bench_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup");

    // contains (miss) at different fill levels
    let miss_hash = make_packet_hash(0xFFFF_FFFF);

    for (label, fill) in [("empty", 0u32), ("100K", 100_000), ("400K", 400_000)] {
        let mut list = PacketHashlist::new();
        populate_hashlist(&mut list, fill);

        group.bench_with_input(
            BenchmarkId::new("contains_miss", label),
            &list,
            |b, l| {
                b.iter(|| l.contains(&miss_hash));
            },
        );
    }

    // insert from empty
    group.bench_function("insert", |b| {
        b.iter_custom(|iters| {
            let mut list = PacketHashlist::new();
            let start = std::time::Instant::now();
            for i in 0..iters {
                list.insert(make_packet_hash(i as u32));
            }
            start.elapsed()
        });
    });

    group.finish();
}

fn bench_path_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_table");

    let now = 1_000_000u64;

    for (label, count) in [("100", 100u32), ("1K", 1_000), ("10K", 10_000)] {
        let mut table = PathTable::new();
        populate_path_table(&mut table, count);

        let hit_dest = make_dest_hash(count / 2);
        let miss_dest = make_dest_hash(0xFFFF_FFFF);

        group.bench_with_input(
            BenchmarkId::new("has_path_hit", label),
            &table,
            |b, t| {
                b.iter(|| t.has_path(&hit_dest, now));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("has_path_miss", label),
            &table,
            |b, t| {
                b.iter(|| t.has_path(&miss_dest, now));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("next_hop_hit", label),
            &table,
            |b, t| {
                b.iter(|| t.next_hop(&hit_dest, now));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("next_hop_miss", label),
            &table,
            |b, t| {
                b.iter(|| t.next_hop(&miss_dest, now));
            },
        );
    }

    group.finish();
}

fn bench_ifac(c: &mut Criterion) {
    let mut group = c.benchmark_group("ifac");

    let config = IfacConfig::new(IfacCredentials::NameOnly("benchmark_net"), 16);

    // Build a realistic ~119-byte packet: 2 header bytes + 16 dest + 1 ctx + 100 data
    let mut raw_packet = vec![0x00u8; 119];
    raw_packet[0] = 0x0C; // HEADER_1 flags
    raw_packet[1] = 0x03; // hops

    let masked = ifac_apply(&config, &raw_packet).unwrap();

    group.bench_function("ifac_apply_119B", |b| {
        b.iter(|| ifac_apply(&config, &raw_packet).unwrap());
    });

    group.bench_function("ifac_verify_119B", |b| {
        b.iter(|| ifac_verify(&config, &masked).unwrap());
    });

    group.finish();
}

criterion_group!(benches, bench_dedup, bench_path_table, bench_ifac);
criterion_main!(benches);
