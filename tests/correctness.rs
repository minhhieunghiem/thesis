use bckdf::derive_key_aes128;
use bckdf::expand::{
    VolPrf,
    cmac::CmacExpand,
    hkdf::HkdfExpand,
};
use sha2::Sha256;
use sha1::Sha1;

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
    // Salt is irrelevant as the thesis only implements the Expand step;
    // salt is used in HKDF-Extract to output PRK.
    let prk = h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let info = h("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    let expander = HkdfExpand::<Sha256>::default();
    let okm = expander.expand(&prk, &info, 42);

    assert_eq!(okm, expected_okm, "RFC 5869 A.1 OKM mismatch");
}

#[test]
fn rfc5869_a2_sha256() {
    // Appendix A.2: Longer inputs/outputs
    let prk = h("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
    let info = h("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
                      c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                      d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
                      e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                      f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let expected_okm = h("b11e398dc80327a1c8e7f78c596a4934\
                              4f012eda2d4efad8a050cc4c19afa97c\
                              59045a99cac7827271cb41c65e590e09\
                              da3275600c2f09b8367793a9aca3db71\
                              cc30c58179ec3e87c14c01d5c1f3434f\
                              1d87");

    let expander = HkdfExpand::<Sha256>::default();
    let okm = expander.expand(&prk, &info, 82);

    assert_eq!(okm, expected_okm, "RFC 5869 A.2 OKM mismatch");
}

#[test]
fn rfc5869_a3_sha256() {
    // Appendix A.3: Zero-length salt/info
    let prk = h("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    let info: &[u8] = b"";
    let expected_okm = h("8da4e775a563c18f715f802a063c5a31\
                              b8a11f5c5ee1879ec3454e5f3c738d2d\
                              9d201395faa4b61a96c8");

    let expander = HkdfExpand::<Sha256>::default();
    let okm = expander.expand(&prk, info, 42);

    assert_eq!(okm, expected_okm, "RFC 5869 A.3 OKM mismatch");
}
#[test]
fn rfc5869_a4_sha1(){
    let prk = h("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243");
    let info = h("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm=h("085a01ea1b10f36933068b56efa5ad81\
                              a4f14b822f5b091568a9cdd4f155fda2\
                              c22e422478d305f3f896");
    let expander = HkdfExpand::<Sha1>::default();
    let okm = expander.expand(&prk, &info, 42);
    assert_eq!(okm, expected_okm, "RFC 5869 A.4 OKM mismatch");
}

#[test]
fn rfc5869_a5_sha1() {
    let prk=h("8adae09a2a307059478d309b26c4115a224cfaf6");
    let info = h("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
                          c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                          d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
                          e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                          f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let expected_okm=h("0bd770a74d1160f7c9f12cd5912a06eb\
                              ff6adcae899d92191fe4305673ba2ffe\
                              8fa3f1a4e5ad79f3f334b3b202b2173c\
                              486ea37ce3d397ed034c7f9dfeb15c5e\
                              927336d0441f4c4300e2cff0d0900b52\
                              d3b4");
    let expander = HkdfExpand::<Sha1>::default();
    let okm = expander.expand(&prk, &info, 82);
    assert_eq!(okm, expected_okm, "RFC 5869 A.5 OKM mismatch");
}

#[test]
fn rfc5869_a6_sha1() {
    let prk = h("da8c8a73c7fa77288ec6f5e7c297786aa0d32d01");
    let info: &[u8] = b"";
    let expected_okm = h("0ac1af7002b3d761d1e55298da9d0506\
                                  b9ae52057220a306e07b6b87e8df21d0\
                                  ea00033de03984d34918");
    let expander = HkdfExpand::<Sha1>::default();
    let okm = expander.expand(&prk, &info, 42);
    assert_eq!(okm, expected_okm, "RFC 5869 A.6 OKM mismatch");
}

#[test]
fn rfc5869_a7_sha1() {
    let prk = h("2adccada18779e7c2077ad2eb19d3f3e731385dd");
    let info: &[u8] = b"";
    let expected_okm = h("2c91117204d745f3500d636a62f64f0a\
                                  b3bae548aa53d423b0d1f27ebba6f5e5\
                                  673a081d70cce7acfc48");
    let expander = HkdfExpand::<Sha1>::default();
    let okm = expander.expand(&prk, &info, 42);
    assert_eq!(okm, expected_okm, "RFC 5869 A.7 OKM mismatch");
}