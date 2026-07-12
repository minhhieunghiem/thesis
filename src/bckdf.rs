use crate::combiner::{
    combine_aes128,
    combine_aes192,
    combine_aes256
};
use crate::context::encode;
use crate::expand::VolPrf;

pub fn derive_key_aes128<P>(
    sigma1: &[u8],
    sigma2: &[u8],
    label: u64,
    c1: &[u8],
    c2: &[u8],
    out_len: usize,
    prf: &P,
) -> Vec<u8>
where
    P: VolPrf,
{
    let prk = combine_aes128(sigma1, sigma2);

    let context = encode(label, c1, c2);

    prf.expand(&prk, &context, out_len)
}

/// AES-192 variant.
pub fn derive_key_aes192<P>(
    sigma1: &[u8],
    sigma2: &[u8],
    label: u64,
    c1: &[u8],
    c2: &[u8],
    out_len: usize,
    prf: &P,
) -> Vec<u8>
where
    P: VolPrf,
{
    let prk = combine_aes192(sigma1, sigma2);

    let context = encode(label, c1, c2);

    prf.expand(&prk, &context, out_len)
}

/// AES-256 variant.
pub fn derive_key_aes256<P>(
    sigma1: &[u8],
    sigma2: &[u8],
    label: u64,
    c1: &[u8],
    c2: &[u8],
    out_len: usize,
    prf: &P,
) -> Vec<u8>
where
    P: VolPrf,
{
    let prk = combine_aes256(sigma1, sigma2);

    let context = encode(label, c1, c2);

    prf.expand(&prk, &context, out_len)
}