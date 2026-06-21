# bc-kdf

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
```
k ← BC(σ1; BC(σ2; BC(σ1; 0^bl)))         // combiner — produces a pseudorandom key k
K ← Expand(k; ⟨L; c1; c2⟩; ℓ)             // expansion — vol-PRF, produces ℓ bits
Return K
```
