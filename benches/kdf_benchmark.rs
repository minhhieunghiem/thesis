use bckdf::{
    bckdf::{derive_key_aes128, derive_key_aes256},
    expand::{cmac::CmacExpand, hkdf::HkdfExpand, VolPrf},
};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use std::hint::black_box;
fn bench_full_kdf_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_kdf_time");

    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];
    let label = b"benchmark-label";
    let c1 = b"Alice";
    let c2 = b"Bob";

    // --- AES-128 + CMAC ---
    let prf_cmac = CmacExpand;
    for out_len in [32, 64, 128, 256, 512] {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes128_cmac_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes128(
                        black_box(&sigma1),
                        black_box(&sigma2),
                        black_box(label),
                        black_box(c1),
                        black_box(c2),
                        black_box(len),
                        black_box(&prf_cmac),
                    )
                });
            },
        );
    }

    // --- AES-128 + HKDF-SHA256 ---
    let prf_hkdf = HkdfExpand::<sha2::Sha256>::default();
    for out_len in [32, 64, 128, 256, 512] {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes128_hkdf_sha256_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes128(
                        black_box(&sigma1),
                        black_box(&sigma2),
                        black_box(label),
                        black_box(c1),
                        black_box(c2),
                        black_box(len),
                        black_box(&prf_hkdf),
                    )
                });
            },
        );
    }

    // --- AES-256 + CMAC (needs 32-byte inputs) ---
    let sigma1_256 = [0x11u8; 32];
    let sigma2_256 = [0x22u8; 32];
    for out_len in [32, 64, 128, 256, 512] {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes256_cmac_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes256(
                        black_box(&sigma1_256),
                        black_box(&sigma2_256),
                        black_box(label),
                        black_box(c1),
                        black_box(c2),
                        black_box(len),
                        black_box(&prf_cmac),
                    )
                });
            },
        );
    }

    group.finish();
}

fn bench_expand_only_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_only_time");

    let prk_16 = [0x42u8; 16];
    let prk_32 = [0x42u8; 32];
    let context = b"context-string-for-benchmark";

    // CMAC-Expand (16-byte PRK)
    let cmac = CmacExpand;
    for out_len in [32, 64, 128, 256] {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("cmac_expand_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| cmac.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    // HKDF-Expand SHA-256 (16-byte PRK custom implementation)
    let hkdf_256 = HkdfExpand::<sha2::Sha256>::default();
    for out_len in [32, 64, 128, 256] {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("hkdf_sha256_expand_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| hkdf_256.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    // HKDF-Expand SHA-512 (16-byte PRK)
    let hkdf_512 = HkdfExpand::<sha2::Sha512>::default();
    for out_len in [32, 64, 128, 256] {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("hkdf_sha512_expand_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| hkdf_512.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    group.finish();
}

//Cycle-based benchmark
fn bench_full_kdf_cycles(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("full_kdf_cycles");

    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];
    let sigma1_256 = [0x11u8; 32];
    let sigma2_256 = [0x22u8; 32];
    let label = b"benchmark-label";
    let c1 = b"Alice";
    let c2 = b"Bob";
    let prf_cmac = CmacExpand;
    let prf_hkdf = HkdfExpand::<sha2::Sha256>::default();

    for out_len in [32, 64, 128, 256, 512] {
        group.throughput(Throughput::Bytes(out_len as u64));

        group.bench_with_input(
            BenchmarkId::new("aes128_cmac_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes128(
                        black_box(&sigma1), black_box(&sigma2),
                        black_box(label), black_box(c1), black_box(c2),
                        black_box(len), black_box(&prf_cmac),
                    )
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("aes128_hkdf_sha256_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes128(
                        black_box(&sigma1), black_box(&sigma2),
                        black_box(label), black_box(c1), black_box(c2),
                        black_box(len), black_box(&prf_hkdf),
                    )
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("aes256_cmac_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes256(
                        black_box(&sigma1_256), black_box(&sigma2_256),
                        black_box(label), black_box(c1), black_box(c2),
                        black_box(len), black_box(&prf_cmac),
                    )
                });
            },
        );
    }

    group.finish();
}

fn bench_expand_only_cycles(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("expand_only_cycles");

    let prk_16 = [0x42u8; 16];
    let context = b"context-string-for-benchmark";
    let cmac = CmacExpand;
    let hkdf_256 = HkdfExpand::<sha2::Sha256>::default();
    let hkdf_512 = HkdfExpand::<sha2::Sha512>::default();

    for out_len in [32, 64, 128, 256] {
        group.throughput(Throughput::Bytes(out_len as u64));

        group.bench_with_input(
            BenchmarkId::new("cmac_expand_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| cmac.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("hkdf_sha256_expand_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| hkdf_256.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("hkdf_sha512_expand_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| hkdf_512.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    group.finish();
}
criterion_group!(time_benches, bench_full_kdf_time, bench_expand_only_time);
criterion_group! {
    name = cycle_benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_full_kdf_cycles, bench_expand_only_cycles
}
criterion_main!(time_benches, cycle_benches);