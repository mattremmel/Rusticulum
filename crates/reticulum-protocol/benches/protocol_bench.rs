use std::time::Instant;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use reticulum_core::types::LinkId;
use reticulum_protocol::link::state::LinkActive;
use reticulum_protocol::link::types::{DerivedKey, LinkMode, LinkRole, LinkStats};
use reticulum_protocol::channel::envelope::Envelope;
use reticulum_protocol::resource::transfer::prepare_resource;

fn make_link_active() -> LinkActive {
    let key_bytes = [0x42u8; 64];
    let derived_key = DerivedKey::new(key_bytes);
    let now = Instant::now();

    LinkActive {
        link_id: LinkId::new([0xAA; 16]),
        derived_key,
        role: LinkRole::Initiator,
        mode: LinkMode::default(),
        rtt: 0.025,
        mtu: 500,
        mdu: LinkActive::compute_mdu(500),
        keepalive: LinkActive::compute_keepalive(0.025),
        stale_time: LinkActive::compute_stale_time(LinkActive::compute_keepalive(0.025)),
        activated_at: now,
        last_inbound: now,
        last_outbound: now,
        stats: LinkStats::default(),
        is_stale: false,
        stale_since: None,
    }
}

fn bench_link_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("link_crypto");

    let link = make_link_active();
    let iv = [0x13u8; 16];

    let data_64 = vec![0xABu8; 64];
    let data_1k = vec![0xABu8; 1024];

    for (label, data) in [("64B", &data_64), ("1KB", &data_1k)] {
        group.throughput(Throughput::Bytes(data.len() as u64));

        let ciphertext = link.encrypt_with_iv(data, &iv).unwrap();

        group.bench_with_input(
            BenchmarkId::new("encrypt_with_iv", label),
            data,
            |b, d| {
                b.iter(|| link.encrypt_with_iv(d, &iv).unwrap());
            },
        );
        group.bench_with_input(
            BenchmarkId::new("decrypt", label),
            &ciphertext,
            |b, ct| {
                b.iter(|| link.decrypt(ct.as_slice()).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_envelope(c: &mut Criterion) {
    let mut group = c.benchmark_group("envelope");

    let envelope = Envelope {
        msg_type: 0x0001,
        sequence: 42,
        payload: vec![0xBB; 100],
    };
    let packed = envelope.pack();

    group.bench_function("pack_100B", |b| {
        b.iter(|| envelope.pack());
    });

    group.bench_function("unpack_100B", |b| {
        b.iter(|| Envelope::unpack(&packed).unwrap());
    });

    group.finish();
}

fn bench_prepare_resource(c: &mut Criterion) {
    let mut group = c.benchmark_group("prepare_resource");

    let derived_key = [0x42u8; 64];
    let iv = [0x13u8; 16];
    let random_hash = [0x55u8; 4];

    let data_1k = vec![0xABu8; 1024];
    let data_64k = vec![0xABu8; 65536];

    for (label, data) in [("1KB", &data_1k), ("64KB", &data_64k)] {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("no_compress", label),
            data,
            |b, d| {
                b.iter(|| {
                    prepare_resource(
                        d, &derived_key, &iv, random_hash, None, false, 0, 1, None, None,
                    )
                    .unwrap()
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_link_crypto, bench_envelope, bench_prepare_resource);
criterion_main!(benches);
