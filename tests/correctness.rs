use bckdf::derive_key_aes128;
use bckdf::expand::{
    VolPrf,
    cmac::CmacExpand,
    hkdf::HkdfExpand,
};
use sha2::Sha256;

#[test]
fn cmac_is_deterministic() {
    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];

    let prf = CmacExpand;

    let k1 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    let k2 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    assert_eq!(k1, k2);
}

#[test]
fn hkdf_is_deterministic() {
    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];

    let prf = HkdfExpand::<Sha256>::default();

    let k1 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    let k2 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    assert_eq!(k1, k2);
}

#[test]
fn changing_sigma1_changes_output() {
    let sigma1 = [0x11u8; 16];
    let sigma1_alt = [0x33u8; 16];
    let sigma2 = [0x22u8; 16];

    let prf = CmacExpand;

    let k1 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    let k2 = derive_key_aes128(
        &sigma1_alt,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    assert_ne!(k1, k2);
}

#[test]
fn changing_sigma2_changes_output() {
    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];
    let sigma2_alt = [0x44u8; 16];

    let prf = CmacExpand;

    let k1 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    let k2 = derive_key_aes128(
        &sigma1,
        &sigma2_alt,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    assert_ne!(k1, k2);
}

#[test]
fn changing_label_changes_output() {
    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];

    let prf = CmacExpand;

    let k1 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    let k2 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label2",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    assert_ne!(k1, k2);
}

#[test]
fn changing_context_changes_output() {
    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];

    let prf = CmacExpand;

    let k1 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    let k2 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Charlie",
        b"Bob",
        32,
        &prf,
    );

    assert_ne!(k1, k2);
}

#[test]
fn different_output_lengths() {
    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];

    let prf = CmacExpand;

    let k16 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        16,
        &prf,
    );

    let k32 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf,
    );

    let k64 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        64,
        &prf,
    );

    assert_eq!(k16.len(), 16);
    assert_eq!(k32.len(), 32);
    assert_eq!(k64.len(), 64);
}

#[test]
fn cmac_and_hkdf_produce_different_keys() {
    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];

    let cmac = CmacExpand;
    let hkdf = HkdfExpand::<Sha256>::default();

    let k1 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &cmac,
    );

    let k2 = derive_key_aes128(
        &sigma1,
        &sigma2,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &hkdf,
    );

    assert_ne!(k1, k2);
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}
#[test]
fn rfc5869_a1_sha256() {
    // Appendix A.1: Basic test case with SHA-256
    let prk = h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let info = h("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    let expander = HkdfExpand::<Sha256>::default();
    let okm = expander.expand(&prk, &info, 42);

    assert_eq!(okm, expected_okm, "RFC 5869 A.1 OKM mismatch");
}
