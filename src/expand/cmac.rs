use super::VolPrf;
use aes::{Aes128, cipher::KeyInit};
use cmac::{Cmac, Mac};

pub struct CmacExpand {
    key: [u8; 16],
}

impl CmacExpand {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }
}

impl VolPrf for CmacExpand {
    fn expand(&self, input: &[u8], output: &mut [u8]) {
        let mut pos = 0;
        let mut counter: u32 = 1;

        while pos < output.len() {
            let mut mac = Cmac::<Aes128>::new_from_slice(&self.key).unwrap();
            mac.update(&counter.to_be_bytes());
            mac.update(input);
            let block = mac.finalize().into_bytes();

            let take = (output.len() - pos).min(16);
            output[pos..pos + take].copy_from_slice(&block[..take]);
            pos += take;
            counter += 1;
        }
    }
}