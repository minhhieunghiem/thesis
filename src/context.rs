pub fn encode(label_bits: u64, c1: &[u8], c2: &[u8]) -> Vec<u8> {
    let mut context = Vec::with_capacity(8 + 4 + c1.len() + 4 + c2.len());
    context.extend_from_slice(&label_bits.to_be_bytes());           // Representation of label L as byte array
    context.extend_from_slice(&(c1.len() as u32).to_be_bytes()); // |c1|
    context.extend_from_slice(c1);
    context.extend_from_slice(&(c2.len() as u32).to_be_bytes()); // |c2|
    context.extend_from_slice(c2);
    context
}