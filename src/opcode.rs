use crate::context::{MachineState, I};
use crate::signed::I256;
use keccak_hash::{keccak, keccak256};
use primitive_types::{H256, U256};
use std::ops::{Div, Neg, Rem};

#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum OpCode {
    STOP = 0x0,
    ADD = 0x01,
    MUL = 0x02,
    SUB = 0x03,
    DIV = 0x04,
    SDIV = 0x05,
    MOD = 0x06,
    SMOD = 0x07,
    ADDMOD = 0x08,
    MULMOD = 0x09,
    EXP = 0x0a,
    SIGNEXTEND = 0x0b,

    // 10s: comparisons & bitwise logic operations
    LT = 0x10,
    GT = 0x11,
    SLT = 0x12,
    SGT = 0x13,
    EQ = 0x14,
    ISZERO = 0x15,
    AND = 0x16,
    OR = 0x17,
    XOR = 0x18,
    NOT = 0x19,
    BYTE = 0x1a,
    SHL = 0x1b,
    SHR = 0x1c,
    SAR = 0x1d,

    // 20s: keccak256
    KECCAK256 = 0x20,

    // 30s: environmental information
    ADDRESS = 0x30,
    BALANCE = 0x31,
    ORIGIN = 0x32,
    CALLER = 0x33,
    CALLVALUE = 0x34,
    CALLDATALOAD = 0x35,
    CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37,
    CODESIZE = 0x38,
    CODECOPY = 0x39,
    GASPRICE = 0x3A,
    EXTCODESIZE = 0x3B,
    EXTCODECOPY = 0x3C,
    RETURNDATASIZE = 0x3D,
    RETURNDATACOPY = 0x3E,
    EXTCODEHASH = 0x3F,

    // 40s: block information
    BLOCKHASH = 0x40,
    COINBASE = 0x41,
    TIMESTAMP = 0x42,
    NUMBER = 0x43,
    PREVRANDAO = 0x44,
    GASLIMIT = 0x45,
    CHAINID = 0x46,
    SELFBALANCE = 0x47,
    BASEFEE = 0x48,

    // 50s: stack, memory, storage, and flow operations
    POP = 0x50,
    MLOAD = 0x51,
    MSTORE = 0x52,
    MSTORE8 = 0x53,
    SLOAD = 0x54,
    SSTORE = 0x55,
    JUMP = 0x56,
    JUMPI = 0x57,
    PC = 0x58,
    MSIZE = 0x59,
    GAS = 0x5A,
    JUMPDEST = 0x5B,

    // 5f, 60s & 70s: push operations
    PUSH0 = 0x5F, // place 0 on stack
    PUSH1 = 0x60, // place 1-byte item on stack
    PUSH2 = 0x61,
    PUSH3 = 0x62,
    PUSH4 = 0x63,
    PUSH5 = 0x64,
    PUSH6 = 0x65,
    PUSH7 = 0x66,
    PUSH8 = 0x67,
    PUSH9 = 0x68,
    PUSH10 = 0x69,
    PUSH11 = 0x6A,
    PUSH12 = 0x6B,
    PUSH13 = 0x6C,
    PUSH14 = 0x6D,
    PUSH15 = 0x6E,
    PUSH16 = 0x6F,
    PUSH17 = 0x70,
    PUSH18 = 0x71,
    PUSH19 = 0x72,
    PUSH20 = 0x73,
    PUSH21 = 0x74,
    PUSH22 = 0x75,
    PUSH23 = 0x76,
    PUSH24 = 0x77,
    PUSH25 = 0x78,
    PUSH26 = 0x79,
    PUSH27 = 0x7A,
    PUSH28 = 0x7B,
    PUSH29 = 0x7C,
    PUSH30 = 0x7D,
    PUSH31 = 0x7E,
    PUSH32 = 0x7F, // place 32-byte (full word) item on stack

    // 80s duplication operations
    DUP0 = 0x80, // duplicate 1st stack item
    DUP1 = 0x81,
    DUP2 = 0x82,
    DUP3 = 0x83,
    DUP4 = 0x84,
    DUP5 = 0x85,
    DUP7 = 0x86,
    DUP8 = 0x87,
    DUP9 = 0x88,
    DUP10 = 0x89,
    DUP11 = 0x8A,
    DUP12 = 0x8B,
    DUP13 = 0x8C,
    DUP14 = 0x8D,
    DUP15 = 0x8E,
    DUP16 = 0x8F, // duplicate 16th stack item

    // 90s exchange operations
    SWAP1 = 0x90, // exchange 1st and 2nd stack items
    SWAP2 = 0x91, // exchange 1st and 3rd stack items
    SWAP3 = 0x92,
    SWAP4 = 0x93,
    SWAP5 = 0x94,
    SWAP6 = 0x95,
    SWAP7 = 0x96,
    SWAP8 = 0x97,
    SWAP9 = 0x98,
    SWAP10 = 0x99,
    SWAP11 = 0x9A,
    SWAP12 = 0x9B,
    SWAP13 = 0x9C,
    SWAP14 = 0x9D,
    SWAP15 = 0x9E,
    SWAP16 = 0x9F, // exchange 1st and 17th stack items

    // a0s: looing operations
    LOG0 = 0xA0,
    LOG1 = 0xA1,
    LOG2 = 0xA2,
    LOG3 = 0xA3,
    LOG4 = 0xA4,

    // f0s: system operations
    CREATE = 0xF0,
    CALL = 0xF1,
    CALLCODE = 0xF2,
    RETURN = 0xF3,
    DELEGATECALL = 0xF4,
    CREATE2 = 0xF5,
    STATICCALL = 0xFA,
    REVERT = 0xFD,
    INVALID = 0xFE,
    SELFDESTRUCT = 0xFF,
}

impl From<u8> for OpCode {
    fn from(value: u8) -> Self {
        if value == 0x00 {
            return OpCode::STOP;
        } else if value == 0x01 {
            return OpCode::ADD;
        } else if value == 0x02 {
            return OpCode::MUL;
        } else if value == 0x03 {
            return OpCode::SUB;
        } else if value == 0xFD {
            return OpCode::REVERT;
        } else if value == 0xFE {
            return OpCode::INVALID;
        } else {
            return OpCode::SELFDESTRUCT;
        }
    }
}

impl From<OpCode> for u8 {
    fn from(code: OpCode) -> Self {
        code.into()
    }
}

// apply operation
// return new stack, added count, removed count
pub fn apply_op(
    mut stack: Vec<U256>,
    i: &I,
    ms: &MachineState,
    op: OpCode,
) -> (Vec<U256>, U256, U256) {
    match op {
        OpCode::STOP => {
            let rc = U256::zero();
            let ac = U256::zero();
            (stack, ac, rc)
        }
        OpCode::ADD => {
            // new_stack[0] = old_stack[0] + old_stack[1]
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            let (c, _) = a.overflowing_add(b);
            stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::MUL => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            let (c, _) = a.overflowing_mul(b);
            stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::SUB => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            let (c, _) = a.overflowing_sub(b);
            stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::DIV => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            if b == U256::zero() {
                stack.push(U256::zero());
            } else {
                let (c, _) = a.div_mod(b);
                stack.push(c);
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        // signed div just means that both a and b should be treated as a signed integer instead of
        // the default unsigned 256 bit integer.
        OpCode::SDIV => {
            let a: I256 = stack.pop().unwrap().into();
            let b: I256 = stack.pop().unwrap().into();

            if b.is_zero() {
                stack.push(U256::zero());
            } else if a == I256::min() && b.is_negative_one() {
                stack.push(I256::min().into());
            } else {
                let c = a.div(b);
                stack.push(c.into());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::MOD => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            if b == U256::zero() {
                stack.push(U256::zero());
            } else {
                //let (_, d) = a.div_mod(b);
                //stack.push(d);
                stack.push(a % b);
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::SMOD => {
            let a: I256 = stack.pop().unwrap().into();
            let b: I256 = stack.pop().unwrap().into();
            if b == I256::zero() {
                stack.push(U256::zero());
            } else {
                stack.push(U256::from(a % b));
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::ADDMOD => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            let c = stack.pop().unwrap();
            if c == U256::zero() {
                stack.push(U256::zero());
            } else {
                let (d, _) = a.overflowing_add(b);
                let (_, e) = a.div_mod(d);
                stack.push(e);
            }

            let rc = U256::from(3);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::MULMOD => {
            let a: U256 = stack.pop().unwrap();
            let b: U256 = stack.pop().unwrap();
            let c: U256 = stack.pop().unwrap();
            if c == U256::zero() {
                stack.push(U256::zero());
            } else {
                let (d, _) = a.overflowing_mul(b);
                let (_, e) = a.div_mod(d);
                stack.push(e);
            }

            let rc = U256::from(3);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::EXP => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            let (c, _) = a.overflowing_pow(b);
            stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::SIGNEXTEND => {
            // a represents a data with old size
            // b represents current size in byte(0 to 31)
            // where size 0 means just the minimum byte(8 bits)
            // and 31 means full word
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();

            if b < 32.into() {
                // mask is 7 in minimum.
                let shift = (8 * b.low_u32()) + 7;
                // is sign_bit on?
                let has_sign_bit = a.bit(shift as usize);

                // e.g. 1000 0000 to 0111 1111
                let sign_bit = U256::one() << shift;
                let mask = sign_bit - U256::one();

                if has_sign_bit {
                    // 1111 ... 1000 0000
                    stack.push(a | !mask);
                } else {
                    // 0000 ... 0111 1111
                    stack.push(a & mask);
                }
            } else {
                stack.push(a);
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::LT => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            if a < b {
                stack.push(U256::one());
            } else {
                stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::GT => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            if a > b {
                stack.push(U256::one());
            } else {
                stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::SLT => {
            let a: I256 = stack.pop().unwrap().into();
            let b: I256 = stack.pop().unwrap().into();
            if a < b {
                stack.push(U256::one());
            } else {
                stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::SGT => {
            let a: I256 = stack.pop().unwrap().into();
            let b: I256 = stack.pop().unwrap().into();
            if a > b {
                stack.push(U256::one());
            } else {
                stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::EQ => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            if a == b {
                stack.push(U256::one());
            } else {
                stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::ISZERO => {
            let a = stack.pop().unwrap();
            if a.is_zero() {
                stack.push(U256::one());
            } else {
                stack.push(U256::zero());
            }

            let rc = U256::from(1);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::AND => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            let c = a & b;
            stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::OR => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            let c = a | b;
            stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::XOR => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            let c = a ^ b;
            stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::NOT => {
            let a = stack.pop().unwrap();

            stack.push(!a);

            let rc = U256::from(1);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::BYTE => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();

            if a < 32.into() {
                // for a byte, we take a snapshot of data(i.e. b)
                // where? a-th less significant bits of b
                // e.g. if  a=0, then 248-255,
                //          a=1, 240-247
                //          a=2, 232-239, etc
                // the result is added to `ret`
                // this is essentially shifting at most 248 to right and masking it with 8
                // bits.
                // bits to shift = 248 - (8*a)
                // bit mask = 0xff

                let (c, _) = a.overflowing_mul(U256::from(8));
                let shift_count = U256::from(248) - c;
                let d = (b >> shift_count) & U256::from(0xFF);
                stack.push(d);
            } else {
                stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::SHL => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();

            //let (c, _) = U256::from(2).overflowing_mul(a);
            //let (d, _) = b.overflowing_mul(c);
            //let (_, e) = d.div_mod(U256::MAX);
            //stack.push(e);
            stack.push(b << a);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::SHR => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();

            //let (c, _) = U256::from(2).overflowing_mul(a);
            //let (d, _) = b.div_mod(c);
            //stack.push(d);
            stack.push(b >> a);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::SAR => {
            // XXX:
            let a: I256 = stack.pop().unwrap().into();
            let b = stack.pop().unwrap();

            //let (c, _) = U256::from(2).overflowing_mul(a);
            //let (d, _) = b.div_mod(c);
            //stack.push(d);

            if a.sign() == -1 {
                // fill the newly created 0s on the left
                let lost_bits = U256::MAX << (U256::from(256) - b);
                stack.push(U256::from(a.0 >> b | lost_bits));
            } else {
                stack.push(a.0 >> b);
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::KECCAK256 => {
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();

            // assume that mem is implemented
            // whatever it is, the type will be Vec<u8>
            // XXX: temporary data. this is a 32-byte value from address 0
            let mut data: Vec<u8> = vec![1; 32];
            keccak256(&mut data);

            // now convert [u8] to U256
            let mut ret = U256::zero();
            for d in data {
                ret = ret | d.into();
                ret = ret << 8;
            }
            ret = ret >> 8;

            stack.push(ret);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::ADDRESS => {
            // return address from execution environment: I.address
            stack.push(i.a.clone());
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::BALANCE => {
            // XXX: get real balance
            let a = stack.pop().unwrap();
            stack.push(U256::from(25));
            let rc = U256::from(1);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::ORIGIN => {
            stack.push(i.o);
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::CALLER => {
            // msg.sender
            // XXX: not sure if this is correct
            stack.push(i.s);
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::CALLVALUE => {
            stack.push(i.v);
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::CALLDATALOAD => {
            let a = stack.pop().unwrap();

            let start: usize = a.as_u64().try_into().unwrap();
            let b = a + U256::from(32);
            let end: usize = b.as_u64().try_into().unwrap();

            // all the out of bounds should have 0
            let mut data = vec![0; 32];
            for idx in start..start + 32 {
                if let Some(v) = i.d.get(idx) {
                    // exist!
                    data[idx] = *v;
                }
            }
            // data to U256
            let mut ret = U256::zero();
            for d in data {
                ret = ret | d.into();
                ret = ret << 8;
            }
            ret = ret >> 8;

            stack.push(ret);

            let rc = U256::from(1);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::CALLDATASIZE => {
            stack.push(U256::from(i.d.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::CALLDATACOPY => {
            stack.push(U256::from(i.d.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::CODESIZE => {
            stack.push(U256::from(i.b.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::CODECOPY => {
            // XXX:
            stack.push(U256::from(i.b.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::GASPRICE => {
            stack.push(U256::from(i.p));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::EXTCODESIZE => {
            // XXX:
            // get size of an account's code
            stack.push(U256::from(i.p));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::EXTCODECOPY => {
            // XXX:
            // copy an account's code in memory
            stack.push(U256::from(i.p));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::RETURNDATASIZE => {
            stack.push(U256::from(ms.returndata.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::RETURNDATACOPY => {
            // XXX:
            // copy output data from the previous call to memory
            stack.push(U256::from(i.p));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::EXTCODEHASH => {
            // XXX:
            // get hash of account's code
            stack.push(U256::from(i.p));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }

        OpCode::BLOCKHASH => {
            // XXX:
            // get hash of account's code
            stack.push(U256::from(i.p));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::COINBASE => {
            stack.push(U256::from(i.h.coinbase));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::TIMESTAMP => {
            stack.push(U256::from(i.h.timestamp));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::NUMBER => {
            stack.push(U256::from(i.h.number));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::PREVRANDAO => {
            stack.push(U256::from(i.h.prevrandao));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::GASLIMIT => {
            stack.push(U256::from(i.h.gaslimit));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::CHAINID => {
            stack.push(U256::from(i.h.chainid));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::SELFBALANCE => {
            stack.push(U256::from(i.h.selfbalance));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }
        OpCode::BASEFEE => {
            stack.push(U256::from(i.h.basefee));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (stack, ac, rc)
        }

        _ => {
            panic!("NOT implemented yet");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_context() -> (I, MachineState) {
        let i = I::default();
        let ms = MachineState::default();
        (i, ms)
    }

    #[test]
    fn apply_op_add() {
        let (i, ms) = init_context();
        let cases = vec![
            (vec![U256::zero(), U256::zero()], U256::zero()),
            (vec![U256::one(), U256::zero()], U256::one()),
            (vec![U256::from(2), U256::from(3)], U256::from(5)),
            //(vec![U256::from(-1), U256::from(3)], U256::from(2)),
            //(vec![U256::from(-1), U256::from(-3)], U256::from(-4)),
        ];
        for (given, expected) in cases {
            let (got, _, _) = apply_op(given, &i, &ms, OpCode::ADD);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0], expected);
        }
    }

    #[test]
    fn apply_op_counters() {
        let (i, ms) = init_context();
        let stack = vec![U256::one(), U256::one()];
        let cases = vec![
            (OpCode::STOP, U256::zero(), U256::zero()),
            (OpCode::ADD, U256::from(1), U256::from(2)),
            (OpCode::MUL, U256::from(1), U256::from(2)),
        ];
        for (code, expected_ac, expected_rc) in cases {
            let (_, ac, rc) = apply_op(stack.clone(), &i, &ms, code);
            assert_eq!(ac, expected_ac);
            assert_eq!(rc, expected_rc);
        }
    }

    #[test]
    fn usize_to_op() {
        let cases = vec![
            (0x00, OpCode::STOP),
            (0x01, OpCode::ADD),
            (0x02, OpCode::MUL),
            (0xFD, OpCode::REVERT),
            (0xFE, OpCode::INVALID),
            (0xFF, OpCode::SELFDESTRUCT),
        ];
        for (given, expected) in cases {
            assert_eq!(OpCode::from(given), expected);
        }
    }

    #[test]
    fn twos_complement() {
        // is it different to mult/div integers as signed or unsigned?
        // if they are all the same bits, should it matter?
        //

        // positives
        // 5: 0000 ... 1001
        // 3: 0000 ... 0011
        let a = U256::from(5);
        let b = U256::from(3);

        assert_eq!(a + b, U256::from(8));
        assert_eq!(a * b, U256::from(15));
        assert_eq!(a / b, U256::from(1));
        assert_eq!(a % b, U256::from(2));

        // negatives
        // 5: 0000 ... 1001
        // -3: 1111 ... 1101
        let a = U256::from(5);
        let b = U256::MAX - 2;

        // add that overflows
        let (result, flow) = a.overflowing_add(b);
        assert!(flow);
        assert_eq!(result, U256::from(2));

        // mult that overflows: result should be -15
        // 15: 0000 ... 1111
        // -15: 1111 ... 0001
        let (result, flow) = a.overflowing_mul(b);
        assert!(flow);
        assert_eq!(result, U256::MAX - 14);

        //assert_eq!(a / b, U256::from(-1));
        // assert_eq!(a % b, U256::from(3));

        // the trouble is when an signed integer that has < 256 bits are represented as U256.
        // how would I know the bits? does EVM take in i32 only if signed?
    }

    #[test]
    fn apply_op_byte() {
        let (i, ms) = init_context();

        //  some data that we want to pick at 255~248
        let data = U256::from(0xA1) << (8 * 31);
        let stack = vec![data, U256::from(0)];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::BYTE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1));

        //  some data that we want to pick at 7~0
        let data = U256::from(0xA1);
        let stack = vec![data, U256::from(31)];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::BYTE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1));

        //  some data that we want to pick at 15~8
        let data = U256::from(0xA1) << 8;
        let stack = vec![data, U256::from(30)];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::BYTE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1));
    }

    #[test]
    fn apply_op_sar() {
        let (i, ms) = init_context();

        // positive A1
        let data = U256::from(0xA1) << 8;
        let stack = vec![U256::from(8), data];

        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::SAR);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1));

        // negative A1
        let data = U256::from(0xA1) << 8 | U256::MAX;
        let stack = vec![U256::from(8), data];

        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::SAR);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1) | U256::MAX);
    }

    #[test]
    fn apply_op_mod() {
        let (i, ms) = init_context();

        let stack = vec![U256::from(3), U256::from(5)];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::MOD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(2));
    }

    #[test]
    fn apply_op_smod() {
        let (i, ms) = init_context();

        let stack = vec![U256::from(7), U256::from(I256::from(-11))];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::SMOD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(3));
    }

    #[test]
    fn apply_op_sdiv() {
        let (i, ms) = init_context();

        let stack = vec![U256::from(4), U256::from(I256::from(-12))];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::SDIV);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(I256::from(-3)));
    }

    #[test]
    fn apply_op_signextend() {
        let (i, ms) = init_context();

        // how to reprsent -1 in 1 byte? 1111 1111
        let stack = vec![U256::from(0), U256::from(0xFF)];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::SIGNEXTEND);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(I256::from(-1)));

        // -1 in 2 byte: 1111 1111 1111 1111
        // it's 2 bytes
        let stack = vec![U256::from(1), U256::from(0xFFFF)];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::SIGNEXTEND);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(I256::from(-1)));
    }

    #[test]
    fn apply_op_keccak256() {
        let (i, ms) = init_context();

        // XXX: load 32-byte value to memory at address 0
        //      we assume this is done.

        // hash 32 bytes from address 0
        let stack = vec![U256::zero(), U256::from(32)];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::KECCAK256);
        assert_eq!(got.len(), 1);

        let mut data = [1; 32];
        keccak256(&mut data);
        let mut expected = U256::zero();
        for d in data {
            expected = expected | d.into();
            expected = expected << 8;
        }
        expected = expected >> 8;

        assert_eq!(got[0], expected);
    }

    #[test]
    fn apply_op_address() {
        let (mut i, ms) = init_context();
        let addr = U256::from(0xffff);
        i.a = addr;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::ADDRESS);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], addr);
    }

    #[test]
    fn apply_op_origin() {
        let (mut i, ms) = init_context();
        let addr = U256::from(0xffff);
        i.o = addr;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::ORIGIN);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], addr);
    }

    #[test]
    fn apply_op_caller() {
        let (mut i, ms) = init_context();
        let addr = U256::from(0xffff);
        i.s = addr;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::CALLER);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], addr);
    }

    #[test]
    fn apply_op_callvalue() {
        let (mut i, ms) = init_context();
        let value = U256::from(0x01);
        i.v = value;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::CALLVALUE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], value);
    }

    #[test]
    fn apply_op_calldataload() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let mut value = U256::from(0xffff) << 248;
        // convert it into vector of u8. big-endian
        let mut data: Vec<u8> = vec![0; 32];
        let mask = 0xff;
        for idx in 0..32 {
            let v = value & mask.into();
            data[31 - idx] = v.low_u32() as u8;

            value = value >> 8;
        }
        i.d = data;

        let stack = vec![U256::from(0x00)];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::CALLDATALOAD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], value);
    }

    #[test]
    fn apply_op_calldatasize() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let mut value = U256::from(0xffff) << 248;
        // convert it into vector of u8. big-endian
        let mut data: Vec<u8> = vec![0; 128];
        let mask = 0xff;
        for idx in 0..128 {
            let v = value & mask.into();
            data[127 - idx] = v.low_u32() as u8;

            value = value >> 8;
        }
        i.d = data;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::CALLDATASIZE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(128));
    }

    #[test]
    fn apply_op_codesize() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let mut value = U256::from(0xffff) << 248;
        // convert it into vector of u8. big-endian
        let mut data: Vec<u8> = vec![0; 128];
        let mask = 0xff;
        for idx in 0..128 {
            let v = value & mask.into();
            data[127 - idx] = v.low_u32() as u8;

            value = value >> 8;
        }
        i.b = data;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::CODESIZE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(128));
    }

    #[test]
    fn apply_op_gasprice() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let gas_price = U256::from(0xAA);
        i.p = gas_price;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::GASPRICE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], gas_price);
    }

    #[test]
    fn apply_op_coinbase() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let coinbase = U256::from(0xAA);
        i.h.coinbase = coinbase;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::COINBASE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], coinbase);
    }

    #[test]
    fn apply_op_timestamp() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let timestamp = U256::from(0xAA);
        i.h.timestamp = timestamp;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::TIMESTAMP);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], timestamp);
    }

    #[test]
    fn apply_op_number() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let number = U256::from(0xAA);
        i.h.number = number;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::NUMBER);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], number);
    }

    #[test]
    fn apply_op_prevrandao() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let prevrandao = U256::from(0xAA);
        i.h.prevrandao = prevrandao;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::PREVRANDAO);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], prevrandao);
    }

    #[test]
    fn apply_op_gaslimit() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let gaslimit = U256::from(0xAA);
        i.h.gaslimit = gaslimit;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::GASLIMIT);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], gaslimit);
    }

    #[test]
    fn apply_op_selfbalance() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let selfbalance = U256::from(0xAA);
        i.h.selfbalance = selfbalance;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::SELFBALANCE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], selfbalance);
    }

    #[test]
    fn apply_op_basefee() {
        let (mut i, ms) = init_context();
        // 256 bits where the left-most byte is set 1.
        let basefee = U256::from(0xAA);
        i.h.basefee = basefee;

        let stack = vec![];
        let (got, _, _) = apply_op(stack, &i, &ms, OpCode::BASEFEE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], basefee);
    }
}
