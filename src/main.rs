use hex::encode;
use bc_kdf::derive_key_aes128;
use bc_kdf::expand::cmac::CmacExpand;
fn main() {
    let sigma1 = [0x11u8; 16];
    let sigma2 = [0x22u8; 16];

    let prf=CmacExpand;

    let key=derive_key_aes128(
        &sigma1,
        &sigma2,
        1,
        b"Alice",
        b"Bob",
        32,
        &prf);

    println!("{}", encode(key));
    }