use hex::encode;
use bckdf::{derive_key_aes128, derive_key_aes256};
use bckdf::expand::cmac::CmacExpand;
fn main() {
    let sigma1_128 = [0x11u8; 16];
    let sigma2_128 = [0x22u8; 16];

    let sigma1_192 = [0x11u8; 24];
    let sigma2_192 = [0x22u8; 24];

    let sigma1_256 = [0x11u8; 32];
    let sigma2_256 = [0x22u8; 32];

    let prf=CmacExpand;

    let key=derive_key_aes128(
        &sigma1_128,
        &sigma2_128,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf);

    println!("{}", encode(key));

    let key2=derive_key_aes256(
        &sigma1_256,
        &sigma2_256,
        b"label",
        b"Alice",
        b"Bob",
        32,
        &prf);

    println!("{}", encode(key2));
    }