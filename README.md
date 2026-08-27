# bckdf

Implementation and performance evaluation of the block-cipher-based key
derivation function (BC-KDF) proposed in Section 7.1 of:

> Matilda Backendal, Sebastian Clermont, Marc Fischlin, Felix Günther.
> **Key Derivation Functions Without a Grain of Salt.**
> Advances in Cryptology – EUROCRYPT 2025.
> IACR ePrint 2025/657. https://eprint.iacr.org/2025/657

This repository is part of a Bachelor's thesis at TU Darmstadt, supervised by
Sebastian Clermont (co-author of the paper above).

---

## What this implements

The construction takes two pieces of key material, σ1 and σ2, and runs them
through a fixed-key combiner followed by a variable-output-length expansion
step:

### Combiner

The combiner uses iterated AES encryption (double encryption with σ₁ on the
outside) over the all-zero block. Both **AES-128** and **AES-256** are
supported. The implementation automatically uses hardware acceleration (AES-NI
on x86_64, ARM Cryptography Extensions on AArch64) when available via the
RustCrypto `aes` crate.
```
k ← BC(σ1; BC(σ2; BC(σ1; 0^bl)))         // combiner — produces a pseudorandom key k
K ← Expand(k; ⟨L; c1; c2⟩; ℓ)             // expansion — vol-PRF, produces ℓ bits
Return K
```

### Expansion

Two expand instantiations are provided:

1. **CMAC-Expand** — Counter-mode chaining over AES-CMAC (NIST SP 800-38B).
   Each block is computed as `Tᵢ = CMACₖ(Tᵢ₋₁ ‖ info ‖ [i])` with a 1-byte
   counter, matching the HKDF-Expand chaining structure (RFC 5869).

2. **HKDF-Expand** — A manually implemented, **digest-generic** RFC 5869
   expand. Unlike the standard `hkdf` crate, this implementation accepts PRKs
   of any length (e.g., a 16-byte AES output as the key for SHA-256 or
   SHA-512 expansion), removing the standard restriction that `|PRK| = hash_len`.

### Context encoding

The context string `⟨L; c1; c2⟩` uses an **injective encoding**:
`|L|₃₂ ‖ L ‖ |c1|₃₂ ‖ c1 ‖ |c2|₃₂ ‖ c2`, where each length field is a fixed
32-bit big-endian integer. This prevents ambiguous parsing regardless of the
payload content.

### PRF-free variant

For comparison, a "PRF-free" mode is also benchmarked: the raw 16-byte
combiner output `k` is used directly as the derived key, bypassing the expand
step entirely.

---

## Repository structure

| Path | Description |
|------|-------------|
| `src/combiner.rs` | AES-128/192/256 combiner (`combine_aes128`, `combine_aes256`) |
| `src/expand/` | Expand implementations (`cmac`, `hkdf`) + `VolPrf` trait |
| `src/expand/cmac.rs` | CMAC-Expand with counter chaining |
| `src/expand/hkdf.rs` | Generic digest-independent HKDF-Expand |
| `src/bckdf.rs` | KDF facade: orchestrates combine → encode → expand |
| `tests/correctness.rs` | Known-answer tests (RFC 4493 CMAC, RFC 5869 HKDF) |
| `benches/kdf_benchmark.rs` | Criterion benchmarks (time + cycles/byte) |

---

## Building and testing

### Requirements

- Rust 1.98+ (stable)
- `hex` crate for test vector decoding (dev-dependency)

### Run correctness tests

```bash
cargo test
```
### Run benchmarks
```bash
# Time-based benchmarks (latency + throughput in MiB/s)
cargo bench --bench kdf_benchmark -- time

# Cycles-per-byte benchmarks (x86_64 only, via RDTSC)
cargo bench --bench kdf_benchmark -- cycles

# PRF-free variant (combiner only)
cargo bench --bench kdf_benchmark -- prf_free

# All benchmarks
cargo bench --bench kdf_benchmark
```
Benchmark results are written to target/criterion/ as interactive HTML
reports.

## Benchmark axes

The evaluation compares the construction along the following axes:

| Axis | Variants |
|------|----------|
| **AES variant** | AES-128 vs. AES-256 |
| **PRF choice** | CMAC-Expand vs. HKDF-Expand (SHA-256 / SHA-512) |
| **Output length** | 32, 64, 128, 256, 512 bytes |
| **Hardware acceleration** | AES-NI / ARM CE enabled vs. software fallback |
| **Architecture** | x86_64 vs. AArch64 |
| **PRF-free** | Combiner only (no expand step) |

---

## Custom technical implementations

- **Generic HKDF-Expand**: A manual RFC 5869 expand implementation generic
  over `Digest`, using `SimpleHmac` with relaxed key-length constraints. This
  allows a 16-byte AES combiner output to serve as the PRK for SHA-256 and
  SHA-512 without intermediate hashing.
- **CMAC-Expand**: A variable-output-length CMAC construction with RFC 5869-
  compatible counter chaining, built atop the fixed-output RustCrypto `cmac`
  crate.
- **Injective encoding**: A length-prefixed context encoding that guarantees
  unambiguous parsing of the label and context fields.
