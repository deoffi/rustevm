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

pub fn vec8_to_u256(data: Vec<u8>) -> U256 {
    // big-endian representation of the slice
    let mut too_much = true;
    let mut b = U256::zero();
    for abyte in data {
        b = b | abyte.into();
        if (b << 8) < b {
            too_much = false;
        } else {
            b = b << 8;
        }
    }
    if too_much {
        // moved 1 too many time
        b = b >> 8;
    }

    b
}

// ADDR(ia, s[ia]n, s, i)
// salt is not empty used by CREATE2
pub fn create_address(caller: H160, caller_nonce: U256, salt: U256, initcode: Vec<u8>) -> H160 {
    // XXX: just random at the moment
    H160::random()
}
