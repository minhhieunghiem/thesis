use cipher::KeyInit;
use hmac::{Mac, SimpleHmac};
use digest::{Digest, OutputSizeUser};
use digest::common::BlockSizeUser;
use typenum::{IsLessOrEqual, Unsigned};

use super::VolPrf;

pub struct HkdfExpand<D>(std::marker::PhantomData<D>);

impl<D> Default for HkdfExpand<D> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<D> VolPrf for HkdfExpand<D>
where
    D: Digest + BlockSizeUser,
// This bound is required for SimpleHmac<D> to implement Mac:
    D::OutputSize: IsLessOrEqual<D::BlockSize>,
{
    fn expand(
        &self,
        prk: &[u8],
        context: &[u8],
        out_len: usize,
    ) -> Vec<u8> {
        let hash_len = <D as OutputSizeUser>::OutputSize::USIZE;
        let n = (out_len + hash_len - 1) / hash_len;

        assert!(
            n <= 255,
            "HKDF expand: requested output too long (max 255 * hash_len)"
        );

        let mut okm = vec![0u8; out_len];
        let mut prev = Vec::new();

        for i in 1..=n {
            let mut mac = SimpleHmac::<D>::new_from_slice(prk)
                .expect("HMAC accepts keys of any length");

            mac.update(&prev);
            mac.update(context);
            mac.update(&[i as u8]);

            let t = mac.finalize().into_bytes();
            let start = (i - 1) * hash_len;
            let end = usize::min(start + hash_len, out_len);
            okm[start..end].copy_from_slice(&t[..end - start]);

            prev = t.to_vec();
        }

        okm
    }
}

#[test]
fn hkdf_expand_works() {
    use sha2::Sha256;
    use crate::expand::hkdf::HkdfExpand;
    use crate::expand::VolPrf;

    let prk = [0x42u8; 16];

    let hkdf = HkdfExpand::<Sha256>::default();

    let key = hkdf.expand(&prk, b"context", 64);

    assert_eq!(key.len(), 64);
    // Verify output is deterministic
    let key2 = hkdf.expand(&prk, b"context", 64);
    assert_eq!(key, key2);
    // Verify different context produces different output
    let key3 = hkdf.expand(&prk, b"other context", 64);
    assert_ne!(key, key3);
}