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