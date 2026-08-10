//Injective encoding |L| || L || |c1| || c1 || |c2| || c2
pub fn encode(label: &[u8], c1: &[u8], c2: &[u8]) -> Vec<u8> {
    let label_len = u32::try_from(label.len()).expect("label too long for u32");
    let c1_len = u32::try_from(c1.len()).expect("c1 too long for u32");
    let c2_len = u32::try_from(c2.len()).expect("c2 too long for u32"); //Rigorous check to prevent u32 truncation

    let mut context = Vec::with_capacity(4 + label.len() + 4 + c1.len() + 4 + c2.len());


    context.extend_from_slice(&label_len.to_be_bytes());
    context.extend_from_slice(label);

    context.extend_from_slice(&c1_len.to_be_bytes());
    context.extend_from_slice(c1);

    context.extend_from_slice(&c2_len.to_be_bytes());
    context.extend_from_slice(c2);
    context
}