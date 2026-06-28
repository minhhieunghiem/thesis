use aes::{Aes128, Aes192, Aes256};
use aes::cipher::{BlockCipherEncrypt, KeyInit};

pub fn combine<C>(sigma1: &[u8], sigma2: &[u8]) -> [u8; 16]
where
    C: KeyInit + BlockCipherEncrypt,
{
    let bc1 = C::new_from_slice(sigma1)
        .expect("σ1 has the wrong length for this AES variant");
    let bc2 = C::new_from_slice(sigma2)
        .expect("σ2 has the wrong length for this AES variant");

    let mut block = [0u8; 16].into(); // 0^bl — all-zero 128-bit block

    bc1.encrypt_block(&mut block); // t1 = BC(σ1; 0^bl)
    bc2.encrypt_block(&mut block); // t2 = BC(σ2; t1)
    bc1.encrypt_block(&mut block); // k  = BC(σ1; t2)

    block.into()
}

pub fn combine_aes128(sigma1: &[u8], sigma2: &[u8]) -> [u8; 16] {
    combine::<Aes128>(sigma1, sigma2)
}
pub fn combine_aes192(sigma1: &[u8], sigma2: &[u8]) -> [u8; 16] {
    combine::<Aes192>(sigma1, sigma2)
}
pub fn combine_aes256(sigma1: &[u8], sigma2: &[u8]) -> [u8; 16] {
    combine::<Aes256>(sigma1, sigma2)
}