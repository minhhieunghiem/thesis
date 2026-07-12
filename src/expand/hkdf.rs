use hkdf::Hkdf;
use sha2::{Sha256, };

use super::VolPrf;

pub struct HkdfExpand;

impl VolPrf for HkdfExpand {
    fn expand(
        &self,
        prk: &[u8],
        context: &[u8],
        out_len: usize
    ) -> Vec<u8> {

        let hkdf = Hkdf::<Sha256>::from_prk(prk)
            .expect("Invalid PRK length.");

        let mut okm = vec![0u8; out_len];

        hkdf.expand(context, &mut okm).expect("Output too long.");

        okm
    }
}

#[test]
fn hkdf_expand_works() {

    use crate::expand::hkdf::HkdfExpand;
    use crate::expand::VolPrf;

    let prk = [0x42u8; 16];

    let hkdf = HkdfExpand;

    let key = hkdf.expand(
        &prk,
        b"context",
        64,
    );


}