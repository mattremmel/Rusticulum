use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use reticulum_crypto::aes_cbc::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use reticulum_crypto::ed25519::Ed25519PrivateKey;
use reticulum_crypto::hkdf::hkdf;
use reticulum_crypto::hmac::hmac_sha256;
use reticulum_crypto::sha::{sha256, sha512, truncated_hash};
use reticulum_crypto::token::Token;
use reticulum_crypto::x25519::X25519PrivateKey;

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    let data_64 = vec![0xABu8; 64];
    let data_1k = vec![0xABu8; 1024];
    let data_64k = vec![0xABu8; 65536];

    for (label, data) in [("64B", &data_64), ("1KB", &data_1k), ("64KB", &data_64k)] {
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_with_input(BenchmarkId::new("sha256", label), data, |b, d| {
            b.iter(|| sha256(d));
        });
        group.bench_with_input(BenchmarkId::new("sha512", label), data, |b, d| {
            b.iter(|| sha512(d));
        });
        group.bench_with_input(BenchmarkId::new("truncated_hash", label), data, |b, d| {
            b.iter(|| truncated_hash(d));
        });
    }

    group.finish();
}

fn bench_symmetric(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric");

    let key_32 = [0x42u8; 32];
    let iv = [0x13u8; 16];
    let key_64 = [0x42u8; 64];

    let data_64 = vec![0xABu8; 64];
    let data_1k = vec![0xABu8; 1024];
    let data_64k = vec![0xABu8; 65536];

    // HMAC
    for (label, data) in [("64B", &data_64), ("1KB", &data_1k)] {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("hmac_sha256", label), data, |b, d| {
            b.iter(|| hmac_sha256(&key_32, d));
        });
    }

    // HKDF
    group.bench_function("hkdf_64B_output", |b| {
        let ikm = [0x55u8; 32];
        b.iter(|| hkdf(64, &ikm, None, None));
    });

    // AES-256-CBC
    for (label, data) in [("64B", &data_64), ("1KB", &data_1k), ("64KB", &data_64k)] {
        group.throughput(Throughput::Bytes(data.len() as u64));

        let ciphertext = aes256_cbc_encrypt(&key_32, &iv, data);

        group.bench_with_input(BenchmarkId::new("aes256_cbc_encrypt", label), data, |b, d| {
            b.iter(|| aes256_cbc_encrypt(&key_32, &iv, d));
        });
        group.bench_with_input(
            BenchmarkId::new("aes256_cbc_decrypt", label),
            &ciphertext,
            |b, ct| {
                b.iter(|| aes256_cbc_decrypt(&key_32, &iv, ct).unwrap());
            },
        );
    }

    // Token encrypt/decrypt
    let token = Token::new(&key_64);
    for (label, data) in [("64B", &data_64), ("1KB", &data_1k)] {
        group.throughput(Throughput::Bytes(data.len() as u64));

        let encrypted = token.encrypt_with_iv(data, &iv);

        group.bench_with_input(
            BenchmarkId::new("token_encrypt", label),
            data,
            |b, d| {
                b.iter(|| token.encrypt_with_iv(d, &iv));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("token_decrypt", label),
            &encrypted,
            |b, enc| {
                b.iter(|| token.decrypt(enc).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_x25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519");

    let priv_a = X25519PrivateKey::from_bytes([0x42u8; 32]);
    let priv_b = X25519PrivateKey::from_bytes([0x55u8; 32]);
    let pub_b = priv_b.public_key();

    group.bench_function("generate", |b| {
        b.iter(|| X25519PrivateKey::generate());
    });

    group.bench_function("diffie_hellman", |b| {
        b.iter(|| priv_a.diffie_hellman(&pub_b));
    });

    group.finish();
}

fn bench_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519");

    let priv_key = Ed25519PrivateKey::from_bytes([0x42u8; 32]);
    let pub_key = priv_key.public_key();
    let message = [0xABu8; 64];
    let signature = priv_key.sign(&message);

    group.bench_function("generate", |b| {
        b.iter(|| Ed25519PrivateKey::generate());
    });

    group.bench_function("sign_64B", |b| {
        b.iter(|| priv_key.sign(&message));
    });

    group.bench_function("verify_64B", |b| {
        b.iter(|| pub_key.verify(&message, &signature).unwrap());
    });

    group.finish();
}

criterion_group!(benches, bench_hashing, bench_symmetric, bench_x25519, bench_ed25519);
criterion_main!(benches);
