use primitive_types::{H160, U256};

// ADDR(ia, s[ia]n, s, i)
// salt is not empty used by CREATE2
pub fn create_address(caller: H160, caller_nonce: U256, salt: U256, initcode: Vec<u8>) -> H160 {
    // XXX: just random at the moment
    H160::random()
}
