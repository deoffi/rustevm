use primitive_types::{H160, U256};
// XXX: use macro?

// H160 to U256
pub fn h160_to_u256(a: H160) -> U256 {
    // addr to U256 is simply adding 12 bytes of zeros on to its left
    let bytes = a.as_bytes();
    let mut slice = [0u8; 32];
    for i in 12..32 {
        slice[i] = bytes[i - 12];
    }

    U256::from_big_endian(&slice)
}

// U256 to H160
pub fn u256_to_h160(a: U256) -> H160 {
    // U256 to H160?
    let mut src = [0u8; 32];
    a.to_big_endian(&mut src);

    H160::from_slice(&src[12..])
}
