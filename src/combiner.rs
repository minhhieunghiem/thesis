use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};

pub fn combine(sigma1: &[u8; 16], sigma2: &[u8; 16]) -> [u8;16]{
    let bc1 = Aes128::new(sigma1.into());
    let bc2 = Aes128::new(sigma2.into());

    let mut block = [0u8;16].into();

    bc1.encrypt_block(&mut block);
    bc2.encrypt_block(&mut block);
    bc1.encrypt_block(&mut block);

    block.into()
}