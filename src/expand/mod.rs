pub(crate) mod cmac;
pub(crate) mod hkdf;

pub trait VolPrf {
    fn expand(&self, input: &[u8], output: &mut [u8]);
}