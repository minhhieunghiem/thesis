use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, Mac};
use digest::KeyInit;
use super::VolPrf;
pub struct CmacExpand128;
pub struct CmacExpand192;
pub struct CmacExpand256;

impl VolPrf for CmacExpand128 {
fn expand(
    &self,
    prk: &[u8],
    context: &[u8],
    output_len: usize,
) -> Vec<u8> {

    let mut output = Vec::with_capacity(output_len);
    let mut prev = Vec::<u8>::new();
    let mut counter: u8 = 1;

    while output.len()<output_len   {
        let mut mac = Cmac::<Aes128>::new_from_slice(prk)
                                    .expect("Invalid PRK length.");
        mac.update(&prev);
        mac.update(context);
        mac.update(&[counter]);


        let block=mac.finalize().into_bytes();
        let to_copy = std::cmp::min(block.len(), output_len - output.len());
        output.extend_from_slice(&block[..to_copy]);

        prev=block.to_vec();
        counter += 1;
    }
    output.truncate(output_len);

    output
}
}

impl VolPrf for CmacExpand192 {
    fn expand(
        &self,
        prk: &[u8],
        context: &[u8],
        output_len: usize,
    ) -> Vec<u8> {
        let mut output = Vec::with_capacity(output_len);
        let mut prev = Vec::<u8>::new();
        let mut counter: u8 = 1;

        while output.len() < output_len {
            let mut mac = Cmac::<Aes192>::new_from_slice(prk)
                .expect("Invalid PRK length.");
            mac.update(&prev);
            mac.update(context);
            mac.update(&[counter]);

            let block = mac.finalize().into_bytes();
            let to_copy = std::cmp::min(block.len(), output_len - output.len());
            output.extend_from_slice(&block[..to_copy]);

            prev = block.to_vec();
            counter += 1;
        }
        output.truncate(output_len);

        output
    }
}

impl VolPrf for CmacExpand256 {
    fn expand(
        &self,
        prk: &[u8],
        context: &[u8],
        output_len: usize,
    ) -> Vec<u8> {
        let mut output = Vec::with_capacity(output_len);
        let mut prev = Vec::<u8>::new();
        let mut counter: u8 = 1;

        while output.len() < output_len {
            let mut mac = Cmac::<Aes256>::new_from_slice(prk)
                .expect("Invalid PRK length.");
            mac.update(&prev);
            mac.update(context);
            mac.update(&[counter]);

            let block = mac.finalize().into_bytes();
            let to_copy = std::cmp::min(block.len(), output_len - output.len());
            output.extend_from_slice(&block[..to_copy]);

            prev = block.to_vec();
            counter += 1;
        }
        output.truncate(output_len);

        output
    }
}

#[cfg(test)]
mod tests {
    use hex::encode;

    use crate::expand::VolPrf;
    use crate::expand::cmac::{CmacExpand128, CmacExpand192, CmacExpand256};

    #[test]
    fn expand_to_64_bytes() {
        let prk128 = [0u8; 16];
        let prk192 = [0u8; 24];
        let prk256 = [0u8; 32];

        let ctx = b"example";

        let cmac128 = CmacExpand128;
        let cmac192 = CmacExpand192;
        let cmac256 = CmacExpand256;

        let key128 = cmac128.expand(&prk128, ctx, 64);
        let key192 = cmac192.expand(&prk192, ctx, 64);
        let key256 = cmac256.expand(&prk256, ctx, 64);

        assert_eq!(key128.len(), 64);
        assert_eq!(key192.len(), 64);
        assert_eq!(key256.len(), 64);

        println!("128: {}", encode(&key128));
        println!("192: {}", encode(&key192));
        println!("256: {}", encode(&key256));
    }

    #[test]
    fn deterministic() {
        let prk128 = [7u8; 16];
        let prk192 = [7u8; 24];
        let prk256 = [7u8; 32];

        let ctx = b"context";

        let cmac128 = CmacExpand128;
        let cmac192 = CmacExpand192;
        let cmac256 = CmacExpand256;

        assert_eq!(
            cmac128.expand(&prk128, ctx, 64),
            cmac128.expand(&prk128, ctx, 64),
        );

        assert_eq!(
            cmac192.expand(&prk192, ctx, 64),
            cmac192.expand(&prk192, ctx, 64),
        );

        assert_eq!(
            cmac256.expand(&prk256, ctx, 64),
            cmac256.expand(&prk256, ctx, 64),
        );
    }
}