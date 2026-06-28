use super::VolPrf;
use hkdf::Hkdf;
use digest::Digest;
use std::marker::PhantomData;

pub struct HkdfExpand<H: Digest> {
    key: Vec<u8>,
    _hash: PhantomData<H>,
}

impl<H: Digest> HkdfExpand<H> {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec(), _hash: PhantomData }
    }
}

impl<H: Digest> VolPrf for HkdfExpand<H> {
    fn expand(&self, input: &[u8], output: &mut [u8]) {
        let hkdf = Hkdf::<H>::from_prk(&self.key)
            .expect("key too short for this hash function's output size");
        hkdf.expand(input, output)
            .expect("output length exceeds HKDF maximum for this hash");
    }
}