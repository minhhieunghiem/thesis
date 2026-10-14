use bckdf::{
    bckdf::{derive_key_aes128, derive_key_aes192, derive_key_aes256},
    expand::{
        cmac::{CmacExpand128, CmacExpand192, CmacExpand256},
        hkdf::HkdfExpand,
        VolPrf,
    },
};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Full KDF — wall-clock time
// ---------------------------------------------------------------------------

fn bench_full_kdf_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_kdf_time");

    let sigma1_128 = [0x11u8; 16];
    let sigma2_128 = [0x22u8; 16];
    let sigma1_192 = [0x11u8; 24];
    let sigma2_192 = [0x22u8; 24];
    let sigma1_256 = [0x11u8; 32];
    let sigma2_256 = [0x22u8; 32];
    let label = b"benchmark-label";
    let c1 = b"Alice";
    let c2 = b"Bob";

    let prf_cmac = CmacExpand128;
    let prf_hkdf = HkdfExpand::<sha2::Sha256>::default();

    let lengths = [32, 64, 128, 256, 512];

    // --- AES-128 + CMAC ---
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes128_cmac_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes128(
                        black_box(&sigma1_128),
                        black_box(&sigma2_128),
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
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes128_hkdf_sha256_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes128(
                        black_box(&sigma1_128),
                        black_box(&sigma2_128),
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

    // --- AES-256 + CMAC ---
    for out_len in lengths {
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

    // --- AES-256 + HKDF-SHA256 ---
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes256_hkdf_sha256_time", out_len),
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
                        black_box(&prf_hkdf),
                    )
                });
            },
        );
    }

     // --- AES-192 + CMAC ---

     for out_len in lengths {
         group.throughput(Throughput::Bytes(out_len as u64));
         group.bench_with_input(
             BenchmarkId::new("aes192_cmac_time", out_len),
             &out_len,
             |b, &len| {
                 b.iter(|| {
                     derive_key_aes192(
                         black_box(&sigma1_192),
                         black_box(&sigma2_192),
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

    //AES-192 + HKDF
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes192_cmac_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes192(
                        black_box(&sigma1_192),
                        black_box(&sigma2_192),
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

    group.finish();
}

// ---------------------------------------------------------------------------
// Expand-only — wall-clock time
// ---------------------------------------------------------------------------

fn bench_expand_only_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_only_time");

    let prk_16 = [0x42u8; 16];
    let context = b"context-string-for-benchmark";
    let lengths = [32, 64, 128, 256];

    // CMAC-Expand-128 (16-byte PRK)
    let cmac128 = CmacExpand128;
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("cmac_expand128_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| cmac128.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    // CMAC-Expand-192 (16-byte PRK)
    let cmac192 = CmacExpand192;
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("cmac_expand192_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| cmac192.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    // CMAC-Expand-256 (16-byte PRK)
    let cmac256 = CmacExpand256;
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("cmac_expand256_time", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| cmac256.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    // HKDF-Expand SHA-256 (16-byte PRK custom implementation)
    let hkdf_256 = HkdfExpand::<sha2::Sha256>::default();
    for out_len in lengths {
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
    for out_len in lengths {
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

// ---------------------------------------------------------------------------
// Full KDF — cycles per byte
// ---------------------------------------------------------------------------

fn bench_full_kdf_cycles(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("full_kdf_cycles");

    let sigma1_128 = [0x11u8; 16];
    let sigma2_128 = [0x22u8; 16];
    let sigma1_192 = [0x11u8; 24];
    let sigma2_192 = [0x22u8; 24];
    let sigma1_256 = [0x11u8; 32];
    let sigma2_256 = [0x22u8; 32];
    let label = b"benchmark-label";
    let c1 = b"Alice";
    let c2 = b"Bob";

    let prf_cmac = CmacExpand128;
    let prf_hkdf = HkdfExpand::<sha2::Sha256>::default();

    let lengths = [32, 64, 128, 256, 512];

    // --- AES-128 + CMAC ---
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes128_cmac_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes128(
                        black_box(&sigma1_128),
                        black_box(&sigma2_128),
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
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes128_hkdf_sha256_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes128(
                        black_box(&sigma1_128),
                        black_box(&sigma2_128),
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

    // --- AES-256 + CMAC ---
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes256_cmac_cycles", out_len),
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

    // --- AES-256 + HKDF-SHA256 ---
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes256_hkdf_sha256_cycles", out_len),
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
                        black_box(&prf_hkdf),
                    )
                });
            },
        );
    }

    // --- AES-192 + CMAC ---
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes192_hkdf_cmac_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes256(
                        black_box(&sigma1_192),
                        black_box(&sigma2_192),
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

    // --- AES-192 + HKDF-SHA256
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("aes192_hkdf_sha256_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| {
                    derive_key_aes256(
                        black_box(&sigma1_192),
                        black_box(&sigma2_192),
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
    group.finish();
}

// ---------------------------------------------------------------------------
// Expand-only — cycles per byte
// ---------------------------------------------------------------------------

fn bench_expand_only_cycles(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("expand_only_cycles");

    let prk_16 = [0x42u8; 16];
    let context = b"context-string-for-benchmark";
    let lengths = [32, 64, 128, 256];

    // CMAC-Expand-128
    let cmac128 = CmacExpand128;
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("cmac_expand128_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| cmac128.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    // CMAC-Expand-192
    let cmac192 = CmacExpand192;
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("cmac_expand192_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| cmac192.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    // CMAC-Expand-256
    let cmac256 = CmacExpand256;
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("cmac_expand256_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| cmac256.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    // HKDF-Expand SHA-256
    let hkdf_256 = HkdfExpand::<sha2::Sha256>::default();
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::new("hkdf_sha256_expand_cycles", out_len),
            &out_len,
            |b, &len| {
                b.iter(|| hkdf_256.expand(black_box(&prk_16), black_box(context), black_box(len)));
            },
        );
    }

    // HKDF-Expand SHA-512
    let hkdf_512 = HkdfExpand::<sha2::Sha512>::default();
    for out_len in lengths {
        group.throughput(Throughput::Bytes(out_len as u64));
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

// ---------------------------------------------------------------------------
// Combine-only — wall-clock time
// ---------------------------------------------------------------------------

fn combine_only_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("combine_only_time");

    let sigma1_128 = [0x11u8; 16];
    let sigma2_128 = [0x22u8; 16];
    let sigma1_192 = [0x11u8; 24];
    let sigma2_192 = [0x22u8; 24];
    let sigma1_256 = [0x11u8; 32];
    let sigma2_256 = [0x22u8; 32];

    group.bench_function("aes128", |b| {
        b.iter(|| {
            bckdf::combiner::combine_aes128(
                black_box(&sigma1_128),
                black_box(&sigma2_128),
            )
        });
    });

    group.bench_function("aes192", |b| {
        b.iter(|| {
            bckdf::combiner::combine_aes192(
                black_box(&sigma1_192),
                black_box(&sigma2_192),
            )
        });
    });

    group.bench_function("aes256", |b| {
        b.iter(|| {
            bckdf::combiner::combine_aes256(
                black_box(&sigma1_256),
                black_box(&sigma2_256),
            )
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Combine-only — cycles per byte
// ---------------------------------------------------------------------------

fn combine_only_cycles(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("combine_only_cycles");

    let sigma1_128 = [0x11u8; 16];
    let sigma2_128 = [0x22u8; 16];
    let sigma1_192 = [0x11u8; 24];
    let sigma2_192 = [0x22u8; 24];
    let sigma1_256 = [0x11u8; 32];
    let sigma2_256 = [0x22u8; 32];

    group.bench_function("aes128", |b| {
        b.iter(|| {
            bckdf::combiner::combine_aes128(
                black_box(&sigma1_128),
                black_box(&sigma2_128),
            )
        });
    });

    group.bench_function("aes192", |b| {
        b.iter(|| {
            bckdf::combiner::combine_aes192(
                black_box(&sigma1_192),
                black_box(&sigma2_192),
            )
        });
    });

    group.bench_function("aes256", |b| {
        b.iter(|| {
            bckdf::combiner::combine_aes256(
                black_box(&sigma1_256),
                black_box(&sigma2_256),
            )
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

criterion_group!(
    time_benches,
    bench_full_kdf_time,
    bench_expand_only_time,
    combine_only_time
);

criterion_group! {
    name = cycle_benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets =
        bench_full_kdf_cycles,
        bench_expand_only_cycles,
        combine_only_cycles
}

criterion_main!(time_benches, cycle_benches);