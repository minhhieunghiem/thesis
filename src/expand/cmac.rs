use aes::Aes128;
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

    let mut counter: u32 = 1;

    while output.len()<output_len   {
        let mut mac = Cmac::<Aes128>::new_from_slice(prk)
                                    .expect("Invalid PRK length.");
        mac.update(&counter.to_be_bytes());
        mac.update(context);

        let block=mac.finalize().into_bytes();

        output.extend_from_slice(&block);

        counter += 1;
    }
    output.truncate(output_len);

    output
}
}

#[cfg(test)]
mod tests {

    use crate::expand::{VolPrf};
    use crate::expand::cmac::CmacExpand;

    #[test]
    fn expand_to_32_bytes() {

        let prk = [0u8;16];

        let ctx = b"example";

        let cmac = CmacExpand;

        let key = cmac.expand(&prk, ctx, 32);

        assert_eq!(key.len(), 32);
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