use hex::encode;
use bckdf::{derive_key_aes128, derive_key_aes256};
use bckdf::expand::cmac::CmacExpand;
use chacha20::ChaCha12Rng;
use rand::{SeedableRng, Rng, rngs::SysRng, RngExt};
use sha2::Sha256;
use bckdf::expand::hkdf::HkdfExpand;

fn main() {
    let mut rng = ChaCha12Rng::try_from_rng(&mut SysRng).unwrap();

    let mut sigma1_128 = [0u8; 16];
    let mut sigma2_128 = [0u8; 16];


    let mut sigma1_192 = [0u8; 24];
    let mut sigma2_192 = [0u8; 24];

    let mut sigma1_256 = [0u8; 32];
    let mut sigma2_256 = [0u8; 32];

    rng.fill(&mut sigma1_128);
    rng.fill(&mut sigma2_128);
    rng.fill(&mut sigma1_192);
    rng.fill(&mut sigma2_192);
    rng.fill(&mut sigma1_256);
    rng.fill(&mut sigma2_256);

    let cmac =CmacExpand;
    let hkdf_sha2 = HkdfExpand::<Sha256>::default();

    let key=derive_key_aes128(
        &sigma1_128,
        &sigma2_128,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &cmac);

    println!("{}", encode(key));

    let key2=derive_key_aes256(
        &sigma1_256,
        &sigma2_256,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &cmac);

    println!("{}", encode(key2));
    }