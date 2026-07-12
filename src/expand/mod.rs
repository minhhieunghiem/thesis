pub mod cmac;
mod hkdf;

pub trait VolPrf {
    fn expand(
        &self,
        prk: &[u8],
        context: &[u8],
        out_len: usize,
    ) -> Vec<u8>;
}