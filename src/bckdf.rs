use crate::combiner::combine;
use crate::context::encode;
use crate::expand::{cmac::CmacExpand, hkdf::HkdfExpand, VolPrf};

pub fn bc_kdf_cmac(
    sigma1: &[u8; 16],
    sigma2: &[u8; 16],
    c1: &[u8],
    c2: &[u8],
    output: &mut [u8],
) {
    let k   = combine(sigma1, sigma2);
    let context = encode((output.len() * 8) as u64, c1, c2);
    CmacExpand::new(k).expand(&context, output);
}

pub fn bc_kdf_hkdf(
    sigma1: &[u8; 16],
    sigma2: &[u8; 16],
    c1: &[u8],
    c2: &[u8],
    output: &mut [u8],
) {
    let k   = combine(sigma1, sigma2);
    let context = encode((output.len() * 8) as u64, c1, c2);
    HkdfExpand::new(&k).expand(&context, output);
}