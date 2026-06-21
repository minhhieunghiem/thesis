use super::VolPrf;
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::Sha3_256;

pub struct HkdfExpand {
    key: Vec<u8>,
}

impl HkdfExpand {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl VolPrf for HkdfExpand {
    fn expand(&self, input: &[u8], output: &mut [u8]) {
        let hkdf = Hkdf::<Sha3_256>::from_prk(&self.key)
            .expect("key must be at least 32 bytes for SHA-256");
        hkdf.expand(input, output)
            .expect("output length exceeds HKDF maximum");
    }
}