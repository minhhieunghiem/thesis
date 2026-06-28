use crate::combiner::combine;
use crate::context::encode;
use crate::expand::{cmac::CmacExpand, hkdf::HkdfExpand, VolPrf};
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use digest::Digest;

/// CMAC variant — generic over the combiner's AES variant C.
/// CMAC itself is always AES-128 internally (see expand/cmac.rs), since k
/// is always 128 bits regardless of C.
pub fn bc_kdf_cmac<C>(
    sigma1: &[u8],
    sigma2: &[u8],
    c1: &[u8],
    c2: &[u8],
    output: &mut [u8],
)
where
    C: KeyInit + BlockCipherEncrypt,
{
    let k   = combine::<C>(sigma1, sigma2);
    let ctx = encode((output.len() * 8) as u64, c1, c2);
    CmacExpand::new(k).expand(&ctx, output);
}

/// HKDF-Expand variant — generic over both the combiner's AES variant C
/// and the hash function H used by HKDF.
pub fn bc_kdf_hkdf<C, H>(
    sigma1: &[u8],
    sigma2: &[u8],
    c1: &[u8],
    c2: &[u8],
    output: &mut [u8],
)
where
    C: KeyInit + BlockCipherEncrypt,
    H: Digest,
{
    let k   = combine::<C>(sigma1, sigma2);
    let ctx = encode((output.len() * 8) as u64, c1, c2);
    HkdfExpand::<H>::new(&k).expand(&ctx, output);
}