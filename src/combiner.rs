use aes::{Aes128, Aes192, Aes256, Block};
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use cipher::consts::U16;

pub fn combine<C>(sigma1: &[u8], sigma2: &[u8]) -> [u8; 16]
where
    C: KeyInit + BlockCipherEncrypt<BlockSize=U16>,
{
    let bc1 = C::new_from_slice(sigma1)
        .expect("σ1 has the wrong length for this AES variant");
    let bc2 = C::new_from_slice(sigma2)
        .expect("σ2 has the wrong length for this AES variant");

    let mut block = Block::default(); // 0^bl — all-zero 128-bit block

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let s1 = [0x11u8; 16];
        let s2 = [0x22u8; 16];

        let result = combine_aes128(&s1, &s2);

        println!("{}", hex::encode(result));

        assert_eq!(
            combine_aes128(&s1, &s2),
            combine_aes128(&s1, &s2)
        );
    }

    #[test]
    fn changing_sigma1_changes_output() {
        let s1 = [0u8; 16];
        let s1b = [1u8; 16];
        let s2 = [2u8; 16];

        assert_ne!(
            combine_aes128(&s1, &s2),
            combine_aes128(&s1b, &s2)
        );
    }

    #[test]
    fn changing_sigma2_changes_output() {
        let s1 = [0u8; 16];
        let s2 = [1u8; 16];
        let s2b = [2u8; 16];

        assert_ne!(
            combine_aes128(&s1, &s2),
            combine_aes128(&s1, &s2b)
        );
    }

    #[test]
    fn aes192_output_size() {
        let s1 = [0u8; 24];
        let s2 = [1u8; 24];

        assert_eq!(combine_aes192(&s1, &s2).len(), 16);
    }

    #[test]
    fn aes256_output_size() {
        let s1 = [0u8; 32];
        let s2 = [1u8; 32];

        assert_eq!(combine_aes256(&s1, &s2).len(), 16);
    }
}