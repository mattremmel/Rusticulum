use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use reticulum_core::constants::{DestinationType, HeaderType, PacketType, TransportType};
use reticulum_core::framing::hdlc::{hdlc_frame, hdlc_unframe};
use reticulum_core::framing::kiss::{kiss_frame, kiss_unframe};
use reticulum_core::identity::Identity;
use reticulum_core::packet::context::ContextType;
use reticulum_core::packet::flags::PacketFlags;
use reticulum_core::packet::wire::RawPacket;
use reticulum_core::types::DestinationHash;

fn make_header1_packet() -> Vec<u8> {
    let pkt = RawPacket {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 3,
        transport_id: None,
        destination: DestinationHash::new([0xAA; 16]),
        context: ContextType::None,
        data: vec![0xBB; 64],
    };
    pkt.serialize()
}

fn make_header2_packet() -> Vec<u8> {
    let pkt = RawPacket {
        flags: PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: false,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 5,
        transport_id: Some(DestinationHash::new([0xCC; 16])),
        destination: DestinationHash::new([0xDD; 16]),
        context: ContextType::None,
        data: vec![0xEE; 64],
    };
    pkt.serialize()
}

fn bench_packet(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet");

    let h1_raw = make_header1_packet();
    let h2_raw = make_header2_packet();

    group.bench_function("parse_header1", |b| {
        b.iter(|| RawPacket::parse(&h1_raw).unwrap());
    });

    group.bench_function("parse_header2", |b| {
        b.iter(|| RawPacket::parse(&h2_raw).unwrap());
    });

    let h1_pkt = RawPacket::parse(&h1_raw).unwrap();
    let h2_pkt = RawPacket::parse(&h2_raw).unwrap();

    group.bench_function("serialize_header1", |b| {
        b.iter(|| h1_pkt.serialize());
    });

    group.bench_function("serialize_header2", |b| {
        b.iter(|| h2_pkt.serialize());
    });

    group.bench_function("packet_hash_header1", |b| {
        b.iter(|| h1_pkt.packet_hash());
    });

    group.bench_function("packet_hash_header2", |b| {
        b.iter(|| h2_pkt.packet_hash());
    });

    group.finish();
}

fn bench_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("framing");

    let data_64 = vec![0xABu8; 64];
    let data_1k = vec![0xABu8; 1024];

    for (label, data) in [("64B", &data_64), ("1KB", &data_1k)] {
        group.throughput(Throughput::Bytes(data.len() as u64));

        let hdlc_framed = hdlc_frame(data);
        let kiss_framed = kiss_frame(data);

        group.bench_with_input(BenchmarkId::new("hdlc_frame", label), data, |b, d| {
            b.iter(|| hdlc_frame(d));
        });
        group.bench_with_input(
            BenchmarkId::new("hdlc_unframe", label),
            &hdlc_framed,
            |b, framed| {
                b.iter(|| hdlc_unframe(framed).unwrap());
            },
        );
        group.bench_with_input(BenchmarkId::new("kiss_frame", label), data, |b, d| {
            b.iter(|| kiss_frame(d));
        });
        group.bench_with_input(
            BenchmarkId::new("kiss_unframe", label),
            &kiss_framed,
            |b, framed| {
                b.iter(|| kiss_unframe(framed).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_identity(c: &mut Criterion) {
    let mut group = c.benchmark_group("identity");

    group.bench_function("generate", |b| {
        b.iter(|| Identity::generate());
    });

    group.finish();
}

criterion_group!(benches, bench_packet, bench_framing, bench_identity);
criterion_main!(benches);
