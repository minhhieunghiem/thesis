use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, Mac};
use digest::KeyInit;
use super::VolPrf;
pub struct CmacExpand;

impl VolPrf for CmacExpand  {
fn expand(
    &self,
    prk: &[u8],
    context: &[u8],
    output_len: usize,
) -> Vec<u8> {

    assert_eq!(prk.len(), 16, "PRK is 16-byte length");

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

#[cfg(test)]
mod tests {
    use hex::encode;
    use crate::expand::{VolPrf};
    use crate::expand::cmac::CmacExpand;

    #[test]
    fn expand_to_32_bytes() {

        let prk = [0u8;16];

        let ctx = b"example";

        let cmac = CmacExpand;

        let key = cmac.expand(&prk, ctx, 32);

        assert_eq!(key.len(), 32);
        println!("{}", encode(key));
    }

    #[test]
    fn deterministic() {

        let prk = [7u8;16];

        let ctx = b"context";

        let cmac = CmacExpand;

        assert_eq!(
            cmac.expand(&prk, ctx, 64),
            cmac.expand(&prk, ctx, 64),
        );
    }
}