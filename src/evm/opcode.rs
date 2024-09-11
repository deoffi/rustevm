use crate::evm::machine::{LogEntry, MachineState, Substate, TopicSeries};
use crate::evm::signed::I256;
use crate::evm::utils::{create_address, h160_to_u256, u256_to_h160, vec8_to_u256};
use crate::world::{Account, BlockHeader, BlockHeaders, ExecutionEnvironment, SystemState};
use keccak_hash::{keccak, keccak256};
use primitive_types::{H160, H256, U256, U512};
use std::ops::Div;

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
        } else if value == 0x60 {
            return OpCode::PUSH1;
        } else if value == 0x52 {
            return OpCode::MSTORE;
        } else if value == 0xF3 {
            return OpCode::RETURN;
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
        if code == OpCode::STOP {
            return 0x00;
        } else if code == OpCode::ADD {
            return 0x01;
        } else if code == OpCode::MUL {
            return 0x02;
        } else if code == OpCode::SUB {
            return 0x03;
        } else if code == OpCode::PUSH1 {
            return 0x60;
        } else if code == OpCode::MSTORE {
            return 0x52;
        } else if code == OpCode::RETURN {
            return 0xF3;
        } else if code == OpCode::REVERT {
            return 0xFD;
        } else if code == OpCode::INVALID {
            return 0xFE;
        } else {
            return 0xFF;
        }
    }
}

// apply operation
// return new stack, added count, removed count
pub fn apply_op(
    headers: &BlockHeaders,
    world_state: &mut SystemState,
    machine_state: &mut MachineState,
    substates: &mut Vec<Substate>,
    env: &ExecutionEnvironment,
    op: OpCode,
) -> (Vec<U256>, U256, U256) {
    match op {
        OpCode::STOP => {
            let rc = U256::zero();
            let ac = U256::zero();
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::ADD => {
            // new_stack[0] = old_stack[0] + old_stack[1]
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let (c, _) = a.overflowing_add(b);
            machine_state.stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::MUL => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let (c, _) = a.overflowing_mul(b);
            machine_state.stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SUB => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let (c, _) = a.overflowing_sub(b);
            machine_state.stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DIV => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            if b == U256::zero() {
                machine_state.stack.push(U256::zero());
            } else {
                let (c, _) = a.div_mod(b);
                machine_state.stack.push(c);
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        // signed div just means that both a and b should be treated as a signed integer instead of
        // the default unsigned 256 bit integer.
        OpCode::SDIV => {
            let a: I256 = machine_state.stack.pop().unwrap().into();
            let b: I256 = machine_state.stack.pop().unwrap().into();

            if b.is_zero() {
                machine_state.stack.push(U256::zero());
            } else if a == I256::min() && b.is_negative_one() {
                machine_state.stack.push(I256::min().into());
            } else {
                let c = a.div(b);
                machine_state.stack.push(c.into());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::MOD => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            if b == U256::zero() {
                machine_state.stack.push(U256::zero());
            } else {
                machine_state.stack.push(a % b);
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SMOD => {
            let a: I256 = machine_state.stack.pop().unwrap().into();
            let b: I256 = machine_state.stack.pop().unwrap().into();
            if b == I256::zero() {
                machine_state.stack.push(U256::zero());
            } else {
                machine_state.stack.push(U256::from(a % b));
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::ADDMOD => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = machine_state.stack.pop().unwrap();
            if c == U256::zero() {
                machine_state.stack.push(U256::zero());
            } else {
                let (d, _) = a.overflowing_add(b);
                let (_, e) = d.div_mod(c);
                machine_state.stack.push(e);
            }

            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::MULMOD => {
            let a: U256 = machine_state.stack.pop().unwrap();
            let b: U256 = machine_state.stack.pop().unwrap();
            let c: U256 = machine_state.stack.pop().unwrap();
            if c == U256::zero() {
                machine_state.stack.push(U256::zero());
            } else {
                let (d, _) = a.overflowing_mul(b);
                let (_, e) = d.div_mod(c);
                machine_state.stack.push(e);
            }

            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::EXP => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let (c, _) = a.overflowing_pow(b);
            machine_state.stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SIGNEXTEND => {
            // a represents a data with old size
            // b represents current size in byte(0 to 31)
            // where size 0 means just the minimum byte(8 bits)
            // and 31 means full word
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();

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
                    machine_state.stack.push(a | !mask);
                } else {
                    // 0000 ... 0111 1111
                    machine_state.stack.push(a & mask);
                }
            } else {
                machine_state.stack.push(a);
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::LT => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            if a < b {
                machine_state.stack.push(U256::one());
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::GT => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            if a > b {
                machine_state.stack.push(U256::one());
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SLT => {
            let a: I256 = machine_state.stack.pop().unwrap().into();
            let b: I256 = machine_state.stack.pop().unwrap().into();
            if a < b {
                machine_state.stack.push(U256::one());
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SGT => {
            let a: I256 = machine_state.stack.pop().unwrap().into();
            let b: I256 = machine_state.stack.pop().unwrap().into();
            if a > b {
                machine_state.stack.push(U256::one());
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::EQ => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            if a == b {
                machine_state.stack.push(U256::one());
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::ISZERO => {
            let a = machine_state.stack.pop().unwrap();
            if a.is_zero() {
                machine_state.stack.push(U256::one());
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(1);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::AND => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = a & b;
            machine_state.stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::OR => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = a | b;
            machine_state.stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::XOR => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = a ^ b;
            machine_state.stack.push(c);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::NOT => {
            let a = machine_state.stack.pop().unwrap();

            machine_state.stack.push(!a);

            let rc = U256::from(1);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::BYTE => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();

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
                machine_state.stack.push(d);
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SHL => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();

            machine_state.stack.push(b << a);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SHR => {
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();

            machine_state.stack.push(b >> a);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SAR => {
            let a: I256 = machine_state.stack.pop().unwrap().into();
            let b = machine_state.stack.pop().unwrap();

            if a.sign() == -1 {
                // fill the newly created 0s on the left
                let lost_bits = U256::MAX << (U256::from(256) - b);
                machine_state.stack.push(U256::from(a.0 >> b | lost_bits));
            } else {
                machine_state.stack.push(a.0 >> b);
            }

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::KECCAK256 => {
            // [b, a]
            //  0  1
            //  offset size
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let offset: usize = b.low_u32() as usize;
            let size: usize = a.low_u32() as usize;

            let mut data = machine_state.m.load(offset, size);

            // assume that mem is implemented
            // whatever it is, the type will be Vec<u8>
            // XXX: temporary data. this is a 32-byte value from address 0
            //let mut data: Vec<u8> = vec![1; 32];

            keccak256(&mut data);

            // now convert [u8] to U256
            let mut ret = U256::zero();
            for d in data {
                ret = ret | d.into();
                ret = ret << 8;
            }
            ret = ret >> 8;

            machine_state.stack.push(ret);

            let rc = U256::from(2);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::ADDRESS => {
            // return address from execution environment: I.address
            machine_state.stack.push(h160_to_u256(env.a.clone()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::BALANCE => {
            // input is the address in query. it should be treated as H160?
            // output is the current balance from the world state
            // if there is no account in the mapping, then return 0
            let a = machine_state.stack.pop().unwrap();
            let addr: H160 = u256_to_h160(a);

            let account = world_state.accounts.get(&addr).unwrap();
            machine_state.stack.push(account.balance);

            let rc = U256::from(1);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::ORIGIN => {
            machine_state.stack.push(U256::from(env.o.as_bytes()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CALLER => {
            // msg.sender
            // XXX: not sure if this is correct
            machine_state.stack.push(U256::from(env.s.as_bytes()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CALLVALUE => {
            machine_state.stack.push(env.v);
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CALLDATALOAD => {
            let a = machine_state.stack.pop().unwrap();

            let start: usize = a.as_u64().try_into().unwrap();

            // all the out of bounds should have 0
            let mut data = vec![0; 32];
            for idx in start..start + 32 {
                if let Some(v) = env.d.get(idx) {
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

            machine_state.stack.push(ret);

            let rc = U256::from(1);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CALLDATASIZE => {
            machine_state.stack.push(U256::from(env.d.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CALLDATACOPY => {
            machine_state.stack.push(U256::from(env.d.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CODESIZE => {
            machine_state.stack.push(U256::from(env.b.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CODECOPY => {
            // XXX:
            machine_state.stack.push(U256::from(env.b.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::GASPRICE => {
            machine_state.stack.push(U256::from(env.p));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::EXTCODESIZE => {
            // get size of an account's code
            let a = machine_state.stack.pop().unwrap();
            let addr = u256_to_h160(a);
            let account = world_state.accounts.get(&addr).unwrap();
            machine_state.stack.push(U256::from(account.code.len()));

            let rc = U256::from(1);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::EXTCODECOPY => {
            // copy an account's code in memory

            // XXX: ordering
            // [d, c, b, a]
            //  0  1  2  3
            // address mem-offset code-offset size?
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = machine_state.stack.pop().unwrap();
            let d = machine_state.stack.pop().unwrap();

            let addr: H160 = u256_to_h160(d);
            let memory_offset: usize = c.low_u32() as usize;
            let code_offset: usize = b.low_u32() as usize;
            let size: usize = a.low_u32() as usize;

            // get account
            if let Some(account) = world_state.accounts.get(&addr) {
                // read code
                let code = &account.code[code_offset..code_offset + size];

                // store in memory
                machine_state.m.store(memory_offset, code.to_vec());
            }

            let rc = U256::from(4);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::RETURNDATASIZE => {
            machine_state
                .stack
                .push(U256::from(machine_state.returndata.len()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::RETURNDATACOPY => {
            // copy output data from the previous call to memory

            // XXX: confused on ordering
            // [c, b, a]
            //  0  1  2
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = machine_state.stack.pop().unwrap();

            let memory_offset = c.low_u32() as usize;
            let data_offset = b.low_u32() as usize;
            let size = a.low_u32() as usize;

            let data = &machine_state.returndata[data_offset..data_offset + size];

            // copy to memory
            machine_state.m.store(memory_offset, data.into());

            let rc = U256::from(3);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::EXTCODEHASH => {
            // get hash of account's code
            let a = machine_state.stack.pop().unwrap();
            let addr = u256_to_h160(a);
            let account = world_state.accounts.get(&addr).unwrap();
            let h = keccak(account.code.clone());
            let code_hash: U256 = U256::from(h.as_bytes());

            machine_state.stack.push(U256::from(code_hash));

            let rc = U256::from(1);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }

        // block
        OpCode::BLOCKHASH => {
            // get block hash of the given block number
            let a = machine_state.stack.pop().unwrap();

            if let Some(header) = headers.get(a) {
                // to U256
                println!("a given: {:?}", a);
                println!("header.blockhash: {:?}", header.blockhash);
                let bytes = header.blockhash.as_bytes();
                machine_state.stack.push(U256::from(bytes));
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(1);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::COINBASE => {
            machine_state.stack.push(U256::from(env.h.coinbase));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::TIMESTAMP => {
            machine_state.stack.push(U256::from(env.h.timestamp));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::NUMBER => {
            machine_state.stack.push(U256::from(env.h.number));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PREVRANDAO => {
            machine_state.stack.push(U256::from(env.h.prevrandao));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::GASLIMIT => {
            machine_state.stack.push(U256::from(env.h.gaslimit));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CHAINID => {
            machine_state.stack.push(U256::from(env.h.chainid));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SELFBALANCE => {
            machine_state.stack.push(U256::from(env.h.selfbalance));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::BASEFEE => {
            machine_state.stack.push(U256::from(env.h.basefee));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }

        // memory
        OpCode::POP => {
            machine_state.stack.pop().unwrap();
            let rc = U256::from(1);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::MLOAD => {
            // in yellowpaper, u'[0] = um[u[0] ... u[0]+31]
            let a = machine_state.stack.pop().unwrap();

            // returns Vec<u8> of size 32
            let data = machine_state.m.load(a.low_u32() as usize, 32);

            // this will fit into U256
            // but would the order by big-endian or little-endian?
            // e.g. given a vector of [0xff, 0xf1, 0x12, ... 0x04, 0x22, 0x01]
            // should U256 be         0xff0xf10x12...0x040x220x01
            //              or        0x010x220x04...0x120xf10xff
            //
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

            machine_state.stack.push(b);

            let rc = U256::from(1);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::MSTORE => {
            // XXX: confusion on order
            // in stack: [b, a]
            // in yellowpaper, memory[b] = a
            // but we favor memory[a] = b just b/c it read easier?
            // do  memory[a] = b and see what happens
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();

            let offset = a.low_u32() as usize;
            let mut data = b;

            // U256 b should be converted into Vec<u8>. Representation is big-endian
            // Vec<u8> will have a size of 32
            let mut word: Vec<u8> = vec![0; 32];
            let last_index = word.len() - 1;
            let mask: u8 = 0xff;
            for i in 0..32 {
                // take the last 8 bits from `b`
                let value = (data & mask.into()).low_u32() as u8;
                word[last_index - i] = value;
                data = data >> 8;
            }
            println!("saving {:?} at {:?}", word, offset);
            machine_state.m.store(offset, word);
            println!("saved!");

            let rc = U256::from(2);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::MSTORE8 => {
            // [b, a]
            // mem[b] = a
            // BUT the current imp does mem[a] = b
            // and the tests are setup that way.
            // not sure if it's true if PUSH1 0x42 and PUSH1 0 MSTORE should store something at 0
            // for 42. it suresly does that.
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();

            let data = vec![b.low_u32() as u8];
            machine_state.m.store(a.low_u32() as usize, data);

            let rc = U256::from(2);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }

        OpCode::SLOAD => {
            // load word from storage
            let a = machine_state.stack.pop().unwrap();

            let account = world_state.accounts.get(&env.a).unwrap();
            if let Some(val) = account.storage_root.get(&a) {
                machine_state.stack.push(*val);
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(1);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SSTORE => {
            // store word from storage
            // [b, a]
            // [key, val]
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();

            let account = world_state.accounts.get_mut(&env.a).unwrap();
            account.storage_root.insert(b, a);

            let rc = U256::from(2);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::JUMP => {
            // alter PC.
            let a = machine_state.stack.pop().unwrap();
            machine_state.pc = a;
            let rc = U256::from(1);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::JUMPI => {
            // conditionally alter PC.
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            // [b, a]

            if a != U256::zero() {
                machine_state.pc = b;
            } else {
                machine_state.pc += U256::one();
            }

            let rc = U256::from(2);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PC => {
            // get PC prior to the increment corresponding to this instruction
            machine_state.stack.push(machine_state.pc);
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::MSIZE => {
            // get the size of active memory in bytes
            machine_state
                .stack
                .push(U256::from(machine_state.m.active_size()));
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::GAS => {
            // get the amount of available gas, including the corresponding reduction for the cost
            // of this instruction
            // XXX: you mean *before* the reduction?
            machine_state.stack.push(machine_state.gas_avail);
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::JUMPDEST => {
            // mark a valid destination for jumps
            // this operation has no effect on machine state during execution
            // XXX: what? me no understand
            let rc = U256::from(0);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }

        OpCode::PUSH0 => {
            // place 0 on the stack
            machine_state.stack.push(U256::zero());
            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH1 => {
            // place 1-byte item on stack
            let offset = machine_state.pc.low_u32() as usize + 1;
            let item = &env.b[offset..offset + 1];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH2 => {
            // place 2-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 2];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH3 => {
            // place 3-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 3];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH4 => {
            // place 4-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 4];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH5 => {
            // place 5-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 5];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH6 => {
            // place 6-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 6];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH7 => {
            // place 7-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 7];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH8 => {
            // place 8-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 8];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH9 => {
            // place 9-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 9];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH10 => {
            // place 10-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 10];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH11 => {
            // place 11-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 11];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH12 => {
            // place 12-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 12];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH13 => {
            // place 13-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 13];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH14 => {
            // place 14-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 14];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH15 => {
            // place 15-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 15];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH16 => {
            // place 16-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 16];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH17 => {
            // place 17-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 17];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH18 => {
            // place 18-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 18];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH19 => {
            // place 19-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 19];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH20 => {
            // place 20-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 20];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH21 => {
            // place 21-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 21];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH22 => {
            // place 22-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 22];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH23 => {
            // place 23-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 23];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH24 => {
            // place 24-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 24];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH25 => {
            // place 25-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 25];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH26 => {
            // place 26-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 26];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH27 => {
            // place 27-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 27];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH28 => {
            // place 28-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 28];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH29 => {
            // place 29-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 29];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH31 => {
            // place 30-byte item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let item = &env.b[offset..offset + 30];
            machine_state.stack.push(U256::from(item));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::PUSH32 => {
            // place 32-byte(full word) item on stack
            let offset = machine_state.pc.low_u32() as usize;
            let word = &env.b[offset..offset + 32];
            machine_state.stack.push(U256::from(word));

            let rc = U256::from(0);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }

        // dups
        OpCode::DUP1 => {
            // duplicate 1st stack item
            machine_state.stack.push(machine_state.stack[0].clone());
            let rc = U256::from(1);
            let ac = U256::from(2);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP2 => {
            // duplicate 2nd stack item
            machine_state.stack.push(machine_state.stack[1].clone());
            let rc = U256::from(2);
            let ac = U256::from(3);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP3 => {
            // duplicate 3rd stack item
            machine_state.stack.push(machine_state.stack[2].clone());
            let rc = U256::from(3);
            let ac = U256::from(4);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP4 => {
            // duplicate 4th stack item
            machine_state.stack.push(machine_state.stack[3].clone());
            let rc = U256::from(4);
            let ac = U256::from(5);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP5 => {
            // duplicate 5th stack item
            machine_state.stack.push(machine_state.stack[4].clone());
            let rc = U256::from(5);
            let ac = U256::from(6);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP7 => {
            // duplicate 7th stack item
            machine_state.stack.push(machine_state.stack[6].clone());
            let rc = U256::from(7);
            let ac = U256::from(8);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP8 => {
            // duplicate 8th stack item
            machine_state.stack.push(machine_state.stack[7].clone());
            let rc = U256::from(8);
            let ac = U256::from(9);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP9 => {
            // duplicate 9th stack item
            machine_state.stack.push(machine_state.stack[8].clone());
            let rc = U256::from(9);
            let ac = U256::from(10);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP16 => {
            // duplicate 16th stack item
            machine_state.stack.push(machine_state.stack[15].clone());
            let rc = U256::from(16);
            let ac = U256::from(17);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP10 => {
            // duplicate 10th stack item
            machine_state.stack.push(machine_state.stack[9].clone());
            let rc = U256::from(10);
            let ac = U256::from(11);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP11 => {
            // duplicate 11th stack item
            machine_state.stack.push(machine_state.stack[10].clone());
            let rc = U256::from(11);
            let ac = U256::from(12);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP12 => {
            // duplicate 12th stack item
            machine_state.stack.push(machine_state.stack[11].clone());
            let rc = U256::from(12);
            let ac = U256::from(13);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP13 => {
            // duplicate 13th stack item
            machine_state.stack.push(machine_state.stack[12].clone());
            let rc = U256::from(13);
            let ac = U256::from(14);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP14 => {
            // duplicate 14th stack item
            machine_state.stack.push(machine_state.stack[13].clone());
            let rc = U256::from(14);
            let ac = U256::from(15);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP15 => {
            // duplicate 15th stack item
            machine_state.stack.push(machine_state.stack[14].clone());
            let rc = U256::from(15);
            let ac = U256::from(16);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DUP16 => {
            // duplicate 16th stack item
            machine_state.stack.push(machine_state.stack[15].clone());
            let rc = U256::from(16);
            let ac = U256::from(17);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP1 => {
            // swap 1st and 2nd stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[1].clone();
            machine_state.stack[0] = second;
            machine_state.stack[1] = first;

            let rc = U256::from(2);
            let ac = U256::from(2);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP2 => {
            // swap 1st and 3rd stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[2].clone();
            machine_state.stack[0] = second;
            machine_state.stack[2] = first;

            let rc = U256::from(3);
            let ac = U256::from(3);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP3 => {
            // swap 1st and 4th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[3].clone();
            machine_state.stack[0] = second;
            machine_state.stack[3] = first;

            let rc = U256::from(4);
            let ac = U256::from(4);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP4 => {
            // swap 1st and 5th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[4].clone();
            machine_state.stack[0] = second;
            machine_state.stack[4] = first;

            let rc = U256::from(5);
            let ac = U256::from(5);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP5 => {
            // swap 1st and 6th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[5].clone();
            machine_state.stack[0] = second;
            machine_state.stack[5] = first;

            let rc = U256::from(6);
            let ac = U256::from(6);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP6 => {
            // swap 1st and 7th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[6].clone();
            machine_state.stack[0] = second;
            machine_state.stack[6] = first;

            let rc = U256::from(7);
            let ac = U256::from(7);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP7 => {
            // swap 1st and 8th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[7].clone();
            machine_state.stack[0] = second;
            machine_state.stack[7] = first;

            let rc = U256::from(8);
            let ac = U256::from(8);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP8 => {
            // swap 1st and 9th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[8].clone();
            machine_state.stack[0] = second;
            machine_state.stack[8] = first;

            let rc = U256::from(9);
            let ac = U256::from(9);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP9 => {
            // swap 1st and 10th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[9].clone();
            machine_state.stack[0] = second;
            machine_state.stack[9] = first;

            let rc = U256::from(10);
            let ac = U256::from(10);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP10 => {
            // swap 1st and 11th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[10].clone();
            machine_state.stack[0] = second;
            machine_state.stack[10] = first;

            let rc = U256::from(11);
            let ac = U256::from(11);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP11 => {
            // swap 1st and 12th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[11].clone();
            machine_state.stack[0] = second;
            machine_state.stack[11] = first;

            let rc = U256::from(12);
            let ac = U256::from(12);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP12 => {
            // swap 1st and 13th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[12].clone();
            machine_state.stack[0] = second;
            machine_state.stack[12] = first;

            let rc = U256::from(13);
            let ac = U256::from(13);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP13 => {
            // swap 1st and 14th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[13].clone();
            machine_state.stack[0] = second;
            machine_state.stack[13] = first;

            let rc = U256::from(14);
            let ac = U256::from(14);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP14 => {
            // swap 1st and 15th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[14].clone();
            machine_state.stack[0] = second;
            machine_state.stack[14] = first;

            let rc = U256::from(15);
            let ac = U256::from(15);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP15 => {
            // swap 1st and 16th stack items
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[15].clone();
            machine_state.stack[0] = second;
            machine_state.stack[15] = first;

            let rc = U256::from(16);
            let ac = U256::from(16);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SWAP16 => {
            // swap 1st and 17th stack items
            // XXX: ordering. when you say first, u[0] is it first of the index(aka bottom of the
            // stack) OR the top?
            let first = machine_state.stack[0].clone();
            let second = machine_state.stack[16].clone();
            machine_state.stack[0] = second;
            machine_state.stack[16] = first;

            let rc = U256::from(17);
            let ac = U256::from(17);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::LOG0 => {
            // append log record with no topics
            // [b, a]
            // [offset, size]
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();

            let offset = b.low_u32() as usize;
            let size = a.low_u32() as usize;

            // load data from mem
            let data: Vec<u8> = machine_state.m.load(offset, size);

            let mut new_substate = Substate::default();
            let entry = LogEntry {
                address: env.a,
                topics: TopicSeries::Empty(),
                content: data,
            };
            new_substate.l.push(entry);

            substates.push(new_substate);

            let rc = U256::from(2);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::LOG1 => {
            // append log record with no topics
            // [c, b, a]
            // [offset, size, topic1]
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = machine_state.stack.pop().unwrap();

            let offset = c.low_u32() as usize;
            let size = b.low_u32() as usize;

            // load data from mem
            let data: Vec<u8> = machine_state.m.load(offset, size);

            let mut new_substate = Substate::default();
            let entry = LogEntry {
                address: env.a,
                topics: TopicSeries::One(a),
                content: data,
            };
            new_substate.l.push(entry);

            substates.push(new_substate);

            let rc = U256::from(3);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::LOG2 => {
            // append log record with no topics
            // [d, c, b, a]
            // [offset, size, topic1, topic2]
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = machine_state.stack.pop().unwrap();
            let d = machine_state.stack.pop().unwrap();

            let offset = d.low_u32() as usize;
            let size = c.low_u32() as usize;

            // load data from mem
            let data: Vec<u8> = machine_state.m.load(offset, size);

            let mut new_substate = Substate::default();
            let entry = LogEntry {
                address: env.a,
                topics: TopicSeries::Two(b, a),
                content: data,
            };
            new_substate.l.push(entry);

            substates.push(new_substate);

            let rc = U256::from(4);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::LOG3 => {
            // append log record with no topics
            // [e, d, c, b, a]
            // [offset, size, topic1, topic2, topic3]
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = machine_state.stack.pop().unwrap();
            let d = machine_state.stack.pop().unwrap();
            let e = machine_state.stack.pop().unwrap();

            let offset = e.low_u32() as usize;
            let size = d.low_u32() as usize;

            // load data from mem
            let data: Vec<u8> = machine_state.m.load(offset, size);

            let mut new_substate = Substate::default();
            let entry = LogEntry {
                address: env.a,
                topics: TopicSeries::Three(c, b, a),
                content: data,
            };
            new_substate.l.push(entry);

            substates.push(new_substate);

            let rc = U256::from(5);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::LOG4 => {
            // append log record with no topics
            // [f, e, d, c, b, a]
            // [offset, size, topic1, topic2, topic3, topic4]
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = machine_state.stack.pop().unwrap();
            let d = machine_state.stack.pop().unwrap();
            let e = machine_state.stack.pop().unwrap();
            let f = machine_state.stack.pop().unwrap();

            let offset = f.low_u32() as usize;
            let size = e.low_u32() as usize;

            // load data from mem
            let data: Vec<u8> = machine_state.m.load(offset, size);

            let mut new_substate = Substate::default();
            let entry = LogEntry {
                address: env.a,
                topics: TopicSeries::Four(d, c, b, a),
                content: data,
            };
            new_substate.l.push(entry);

            substates.push(new_substate);

            let rc = U256::from(6);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }

        // systems
        OpCode::CREATE => {
            // create a new account
            // [c, b, a]
            // [value, offset, size]
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = machine_state.stack.pop().unwrap();

            let size = a.low_u32() as usize;
            let offset = b.low_u32() as usize;
            let value = c;

            // here, we have three state changes:
            // - system state: caller's nonce is increased
            // - machine state: gas available(after some use)
            // - machine state: return value(new address)
            // XXX: implement the first two as well
            //      incrementing caller's nonce would requries tx ipmlementation,
            //      which i believe will help me answer the stackoverflow qeustion

            // return value is a new address.
            // new address is `0` if the following contraints are not met:

            // 1. z=0 i.e. the contract creation process failed
            // 2. initcode size > 49152 bytes
            // 3. Ie = 1024; the maximum call depth has reached
            // 4. value > balance of Ia(account that is executing this CREATE)

            // check for #2 and #3
            if env.e < U256::from(1024) && size <= 49152 {
                // caller's account
                let caller = world_state.accounts.get(&env.a).unwrap();
                // check for #4
                if caller.balance < value {
                    machine_state.stack.push(U256::zero());
                } else {
                    // return the newly created address
                    // XXX: where do we get this salt?
                    let salt = U256::zero();
                    // load data from mem
                    let initcode: Vec<u8> = machine_state.m.load(offset, size);
                    let new_addr = create_address(env.a, caller.nonce, salt, initcode);
                    // check for #1: `new_addr` will be zero in case of z=0
                    machine_state.stack.push(U256::from(new_addr.as_bytes()));
                }
            } else {
                machine_state.stack.push(U256::zero());
            }

            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CALL => {
            // message-call into an account
            // [g, f, e, d, c, b, a]
            // [gas, to, value, in offset, in size, out offset, out size]
            let a = machine_state.stack.pop().unwrap();
            let b = machine_state.stack.pop().unwrap();
            let c = machine_state.stack.pop().unwrap();
            let d = machine_state.stack.pop().unwrap();
            let e = machine_state.stack.pop().unwrap();
            let f = machine_state.stack.pop().unwrap();
            let g = machine_state.stack.pop().unwrap();

            let out_size = a.low_u32() as usize;
            let out_offset = b.low_u32() as usize;
            let in_size = c.low_u32() as usize;
            let in_offset = d.low_u32() as usize;
            let value = e;
            let to: H160 = u256_to_h160(f);
            let gas = g;

            // let output = 0;
            // take smaller
            // let mut n = out_size;
            // if n > output.len() {
            //     n = output.len();
            // }

            // here, we have three state changes:

            // returns a new state, new gas avail, accrued substates, x, and o
            // x: not so ture about
            // o: it's a resultant output that is growning

            // phase 1: transitional state
            // apply value transfers
            if let Some(sender) = world_state.accounts.get_mut(&env.s) {
                sender.balance -= value;
            }

            let recipient = world_state.accounts.get_mut(&to).unwrap();
            recipient.balance += value;

            // phase 2: execution state

            // x is z. it indicates if there is a change. 0 if no change, 1 if change
            let x = U256::one();
            machine_state.stack.push(x);

            let rc = U256::from(7);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CALLCODE => {
            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::RETURN => {
            // [offset, size]
            // let a = machine_state.stack.pop().unwrap();
            // let b = machine_state.stack.pop().unwrap();
            //
            // let offset = b.low_u32() as usize;
            // let size = a.low_u32() as usize;
            //
            // // halt with output defined
            // let output = machine_state.m.load(offset, size);
            // let rc = U256::from(2);
            // let ac = U256::from(0);
            let rc = U256::from(0);
            let ac = U256::from(0);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::DELEGATECALL => {
            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::CREATE2 => {
            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::STATICCALL => {
            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::REVERT => {
            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::INVALID => {
            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }
        OpCode::SELFDESTRUCT => {
            let rc = U256::from(3);
            let ac = U256::from(1);
            (machine_state.stack.clone(), ac, rc)
        }

        _ => {
            panic!("NOT implemented yet");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_context() -> (
        ExecutionEnvironment,
        MachineState,
        SystemState,
        Vec<Substate>,
        BlockHeaders,
    ) {
        let i = ExecutionEnvironment::default();
        let ms = MachineState::default();
        let s = SystemState::default();
        let a: Vec<Substate> = vec![];
        let headers = BlockHeaders::default();

        (i, ms, s, a, headers)
    }

    #[test]
    fn apply_op_add() {
        let (i, mut ms, mut s, mut a, headers) = init_context();
        let cases = vec![
            (vec![U256::zero(), U256::zero()], U256::zero()),
            (vec![U256::one(), U256::zero()], U256::one()),
            (vec![U256::from(2), U256::from(3)], U256::from(5)),
            //(vec![U256::from(-1), U256::from(3)], U256::from(2)),
            //(vec![U256::from(-1), U256::from(-3)], U256::from(-4)),
        ];
        for (given, expected) in cases {
            ms.stack = given;
            let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::ADD);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0], expected);
        }
    }

    #[test]
    fn apply_op_counters() {
        let (i, mut ms, mut s, mut a, headers) = init_context();
        let cases = vec![
            (OpCode::STOP, U256::zero(), U256::zero()),
            (OpCode::ADD, U256::from(1), U256::from(2)),
            (OpCode::MUL, U256::from(1), U256::from(2)),
        ];
        for (code, expected_ac, expected_rc) in cases {
            ms.stack = vec![U256::one(), U256::one()];
            let (_, ac, rc) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, code);
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
        let (i, mut ms, mut s, mut a, headers) = init_context();

        //  some data that we want to pick at 255~248
        let data = U256::from(0xA1) << (8 * 31);
        ms.stack = vec![data, U256::from(0)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::BYTE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1));

        //  some data that we want to pick at 7~0
        let data = U256::from(0xA1);
        ms.stack = vec![data, U256::from(31)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::BYTE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1));

        //  some data that we want to pick at 15~8
        let data = U256::from(0xA1) << 8;
        ms.stack = vec![data, U256::from(30)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::BYTE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1));
    }

    #[test]
    fn apply_op_sar() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        // positive A1
        let data = U256::from(0xA1) << 8;
        ms.stack = vec![U256::from(8), data];

        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SAR);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1));

        // negative A1
        let data = U256::from(0xA1) << 8 | U256::MAX;
        ms.stack = vec![U256::from(8), data];

        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SAR);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xA1) | U256::MAX);
    }

    #[test]
    fn apply_op_mod() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        ms.stack = vec![U256::from(3), U256::from(5)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MOD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(2));
    }

    #[test]
    fn apply_op_smod() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        ms.stack = vec![U256::from(7), U256::from(I256::from(-11))];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SMOD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(3));
    }

    #[test]
    fn apply_op_sdiv() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        ms.stack = vec![U256::from(4), U256::from(I256::from(-12))];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SDIV);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(I256::from(-3)));
    }

    #[test]
    fn apply_op_signextend() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        // how to reprsent -1 in 1 byte? 1111 1111
        ms.stack = vec![U256::from(0), U256::from(0xFF)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SIGNEXTEND);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(I256::from(-1)));

        // -1 in 2 byte: 1111 1111 1111 1111
        // it's 2 bytes
        ms.stack = vec![U256::from(1), U256::from(0xFFFF)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SIGNEXTEND);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(I256::from(-1)));
    }

    #[test]
    fn apply_op_keccak256() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        // store 32-byte value to memory at address 12
        let offset: usize = 12;
        let mut data = vec![1u8; 32];
        ms.m.store(offset, data.clone());

        // hash 32 bytes from address 0
        ms.stack = vec![U256::from(offset), U256::from(32)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::KECCAK256);
        assert_eq!(got.len(), 1);

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
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        let addr = U256::from(0xffff);
        i.a = u256_to_h160(addr);

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::ADDRESS);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], addr);
    }

    #[test]
    fn apply_op_balance() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        let addr = H160::from_low_u64_be(123);
        let mut account = Account::default();
        account.balance = U256::from(456);
        s.accounts.insert(addr, account);

        ms.stack = vec![h160_to_u256(addr)];

        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::BALANCE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(456));
    }

    #[test]
    fn apply_op_origin() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        let addr = H160::random();
        i.o = addr;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::ORIGIN);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(addr.as_bytes()));
    }

    #[test]
    fn apply_op_caller() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        let addr = H160::random();
        i.s = addr;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CALLER);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(addr.as_bytes()));
    }

    #[test]
    fn apply_op_callvalue() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        let value = U256::from(0x01);
        i.v = value;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CALLVALUE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], value);
    }

    #[test]
    fn apply_op_calldataload() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
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

        ms.stack = vec![U256::from(0x00)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CALLDATALOAD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], value);
    }

    #[test]
    fn apply_op_calldatasize() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
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

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CALLDATASIZE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(128));
    }

    #[test]
    fn apply_op_codesize() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
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

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CODESIZE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(128));
    }

    #[test]
    fn apply_op_gasprice() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        // 256 bits where the left-most byte is set 1.
        let gas_price = U256::from(0xAA);
        i.p = gas_price;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::GASPRICE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], gas_price);
    }

    #[test]
    fn apply_op_extcodesize() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        let addr = H160::random();
        let mut account = Account::default();
        account.code = vec![1u8; 100];

        s.accounts.insert(addr, account);

        ms.stack = vec![h160_to_u256(addr)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::EXTCODESIZE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(100));
    }

    #[test]
    fn apply_op_extcodecopy() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        let addr = H160::random();
        let mut account = Account::default();
        let mut code = vec![0u8; 100];

        // 12 bytes of code in 12-31
        for i in 12..32 {
            code[i] = 0xfa
        }
        account.code = code;
        s.accounts.insert(addr, account);

        // XXX: ordering
        // 0: address
        // 1: mem offset
        // 2: code offset
        // 3: size
        let memory_offset = U256::from(0x00);
        let code_offset = U256::from(12);
        let size = U256::from(20);
        ms.stack = vec![h160_to_u256(addr), memory_offset, code_offset, size];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::EXTCODECOPY);
        assert_eq!(got.len(), 0);

        // load from memory to check
        let data_in_memory: Vec<u8> =
            ms.m.load(memory_offset.low_u32() as usize, size.low_u32() as usize);

        let expected = vec![0xfa; 20];
        assert_eq!(data_in_memory, expected);
    }

    #[test]
    fn apply_op_returndatasize() {
        let (i, mut ms, mut s, mut a, headers) = init_context();
        ms.returndata = "hello world".to_string();

        ms.stack = vec![];
        let (got, _, _) = apply_op(
            &headers,
            &mut s,
            &mut ms,
            &mut a,
            &i,
            OpCode::RETURNDATASIZE,
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(ms.returndata.len()));
    }

    #[test]
    fn apply_op_returndatacopy() {
        let (i, mut ms, mut s, mut a, headers) = init_context();
        ms.returndata = "hello world".to_string();

        // XXX: ordering
        //      0: memory offset
        //      1: data offset
        //      2: size
        let memory_offset = U256::from(0xff);
        let data_offset = U256::from(6);
        let size = U256::from(5);
        ms.stack = vec![memory_offset, data_offset, size];

        let (got, _, _) = apply_op(
            &headers,
            &mut s,
            &mut ms,
            &mut a,
            &i,
            OpCode::RETURNDATACOPY,
        );
        assert_eq!(got.len(), 0);

        // load from memory to check
        let data_in_memory: Vec<u8> =
            ms.m.load(memory_offset.low_u32() as usize, size.low_u32() as usize);

        assert_eq!(data_in_memory, "world".as_bytes());
    }

    #[test]
    fn apply_op_extcodehash() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        let addr = H160::random();
        let mut account = Account::default();
        let mut code = vec![0u8; 100];

        // 12 bytes of code in 12-31
        for i in 20..32 {
            code[i] = 0xfa
        }
        account.code = code;

        // keccak of code
        let code_hash = keccak(account.code.clone());
        let expected: U256 = U256::from(code_hash.as_bytes());

        s.accounts.insert(addr, account);

        ms.stack = vec![h160_to_u256(addr)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::EXTCODEHASH);
        assert_eq!(got.len(), 1);

        assert_eq!(got[0], expected);
    }

    #[test]
    fn apply_op_blockhash() {
        let (i, mut ms, mut s, mut a, mut headers) = init_context();

        let mut hashes = vec![];
        for i in 0..256 {
            let mut h = BlockHeader::default();
            h.number = U256::from(i);
            // XXX: random hash for the purpose of simplicity
            let hash = H256::random();
            hashes.push(hash);
            h.blockhash = hash;
            headers.push(h);
        }

        let number = U256::from(123);
        ms.stack = vec![number];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::BLOCKHASH);
        assert_eq!(got.len(), 1);
        assert_eq!(hashes.len(), 256);
        let my_hash = U256::from(hashes[123].as_bytes());
        assert_eq!(got[0], my_hash);
    }

    #[test]
    fn apply_op_coinbase() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        // 256 bits where the left-most byte is set 1.
        let coinbase = U256::from(0xAA);
        i.h.coinbase = coinbase;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::COINBASE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], coinbase);
    }

    #[test]
    fn apply_op_timestamp() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        // 256 bits where the left-most byte is set 1.
        let timestamp = U256::from(0xAA);
        i.h.timestamp = timestamp;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::TIMESTAMP);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], timestamp);
    }

    #[test]
    fn apply_op_number() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        // 256 bits where the left-most byte is set 1.
        let number = U256::from(0xAA);
        i.h.number = number;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::NUMBER);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], number);
    }

    #[test]
    fn apply_op_prevrandao() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        // 256 bits where the left-most byte is set 1.
        let prevrandao = U256::from(0xAA);
        i.h.prevrandao = prevrandao;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::PREVRANDAO);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], prevrandao);
    }

    #[test]
    fn apply_op_gaslimit() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        // 256 bits where the left-most byte is set 1.
        let gaslimit = U256::from(0xAA);
        i.h.gaslimit = gaslimit;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::GASLIMIT);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], gaslimit);
    }

    #[test]
    fn apply_op_selfbalance() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        // 256 bits where the left-most byte is set 1.
        let selfbalance = U256::from(0xAA);
        i.h.selfbalance = selfbalance;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SELFBALANCE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], selfbalance);
    }

    #[test]
    fn apply_op_basefee() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        // 256 bits where the left-most byte is set 1.
        let basefee = U256::from(0xAA);
        i.h.basefee = basefee;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::BASEFEE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], basefee);
    }

    #[test]
    fn apply_op_mload() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        ms.stack = vec![U256::from(0xFF)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MLOAD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::zero());
    }

    #[test]
    fn apply_op_mstore() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        // shouldn't it be u[0] = offset and u[1] = data?
        // where translates to:
        // PUSH1 0xAA
        // PUSH1 0xFF
        // MSTORE
        //ms.stack = vec![U256::from(0xAA), U256::from(0xFF)];

        // MSTORE currently does:
        // [b, a]
        // mem[a] = b
        // this translates to
        // PUSH1 0xFF
        // PUSH1 0xAA
        // MSTORE
        ms.stack = vec![U256::from(0xFF), U256::from(0xAA)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MSTORE);
        assert_eq!(got.len(), 0);

        ms.stack = vec![U256::from(0xAA)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MLOAD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(0xFF));
    }

    #[test]
    fn apply_op_mstore8() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        ms.stack = vec![U256::from(0xAA)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MLOAD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::zero());

        ms.stack = vec![U256::from(0xFF), U256::from(0xAA)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MSTORE8);
        assert_eq!(got.len(), 0);

        //ms.stack = vec![U256::from(0xAA - 32)];
        //let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MLOAD);
        //assert_eq!(got.len(), 1);
        //assert_eq!(
        //    got[0],
        //    U256::zero(),
        //    "32-byte starting from {}(0xAA-32) is not zero",
        //    0xAA - 32
        //);
        //
        //ms.stack = vec![U256::from(0xAA + 32)];
        //let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MLOAD);
        //assert_eq!(got.len(), 1);
        //assert_eq!(
        //    got[0],
        //    U256::zero(),
        //    "32-byte starting from {}(0xAA+32) is not zero",
        //    0xAA + 32
        //);
        //
        //ms.stack = vec![U256::from(0xAA - 1)];
        //let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MLOAD);
        //assert_eq!(got.len(), 1);
        //assert_eq!(
        //    got[0],
        //    U256::from(0xFF) << (30 * 8),
        //    "32-byte starting from {}(0xAA-1) is incorrect",
        //    0xAA - 1
        //);
        //
        //ms.stack = vec![U256::from(0x9A)];
        //let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MLOAD);
        //assert_eq!(got.len(), 1);
        //assert_eq!(
        //    got[0],
        //    U256::from(0xFF) << (15 * 8),
        //    "32-byte starting from {}(0x9A) incorrect",
        //    0x9A
        //);

        println!("memory: {:?}", ms.m);
        println!("memory size: {:?}", ms.m.active_size());
        ms.stack = vec![U256::from(0xAA)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MLOAD);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0],
            U256::from(0xFF) << (31 * 8),
            "memory is empty, why!"
        );
    }

    #[test]
    fn apply_op_sload() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();

        // prepopulate account
        let mut account = Account::default();
        let key = U256::from(0xaaaa);
        let value = U256::from(0xffaa);
        account.storage_root.insert(key, value);

        i.a = u256_to_h160(U256::from(0x1234));
        s.accounts.insert(i.a, account);

        ms.stack = vec![key];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SLOAD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], value);
    }

    #[test]
    fn apply_op_sstore() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();

        // prepopulate account
        let mut account = Account::default();
        let key1 = U256::from(0xaaaa);
        let value1 = U256::from(0xffaa);
        account.storage_root.insert(key1, value1);

        i.a = u256_to_h160(U256::from(0x1234));
        s.accounts.insert(i.a, account);

        // key to store and load
        let key2 = U256::from(0xaaaa);
        let value2 = U256::from(0xffaa);

        // vec[0] : key
        // vec[1] : value
        ms.stack = vec![key2, value2];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SSTORE);
        assert_eq!(got.len(), 0);

        // load
        ms.stack = vec![key2];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SLOAD);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], value2);
    }

    #[test]
    fn apply_op_jump() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        ms.pc = U256::from(42);
        let jump = U256::from(2);

        ms.stack = vec![jump];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::JUMP);
        assert_eq!(got.len(), 0);
        assert_eq!(ms.pc, jump);
    }

    #[test]
    fn apply_op_jumpi() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        ms.pc = U256::from(42);
        let jump = U256::from(2);
        let condition = U256::from(123);

        ms.stack = vec![jump, condition];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::JUMPI);
        assert_eq!(got.len(), 0);
        assert_eq!(ms.pc, jump);
    }

    #[test]
    fn apply_op_pc() {
        let (i, mut ms, mut s, mut a, headers) = init_context();
        ms.pc = U256::from(42);
        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::PC);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], ms.pc);
    }

    #[test]
    fn apply_op_msize() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        let data = [1u8; 64].to_vec();
        ms.m.store(0, data);

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::MSIZE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(64));
    }

    #[test]
    fn apply_op_gas() {
        let (i, mut ms, mut s, mut a, headers) = init_context();
        ms.gas_avail = U256::from(22);
        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::GAS);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], ms.gas_avail);
    }

    // XXX: not sure what to test for
    #[test]
    fn apply_op_jumpdest() {
        let (i, mut ms, mut s, mut a, headers) = init_context();
        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::JUMPDEST);
        assert_eq!(got.len(), 0);
    }

    #[test]
    fn apply_op_push() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();
        // the program code's byte array
        let mut program_code = vec![0u8; 64];
        program_code[0] = 0xaa;
        program_code[31] = 0xbb;

        // works b/c pc is at 0
        let byte_1_content = program_code[0].clone();
        let byte_32_content = program_code[..32].to_vec();

        i.b = program_code;

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::PUSH0);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::zero());

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::PUSH1);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(byte_1_content));

        ms.stack = vec![];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::PUSH32);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::from(byte_32_content.as_slice()));
    }

    #[test]
    fn apply_op_dup() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        ms.stack = vec![U256::from(0xAA)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::DUP1);
        assert_eq!(got.len(), 2);
        for g in got {
            assert_eq!(g, U256::from(0xAA));
        }

        ms.stack = vec![U256::zero(); 2];
        ms.stack[1] = U256::from(0xAA);
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::DUP2);
        assert_eq!(got.len(), 3);
        // first is 0 and last two are duplicated
        assert_eq!(got[0], U256::zero());
        assert_eq!(got[1], U256::from(0xAA));
        assert_eq!(got[2], U256::from(0xAA));

        ms.stack = vec![U256::zero(); 16];
        ms.stack[15] = U256::from(0xAA);
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::DUP16);
        assert_eq!(got.len(), 17);
        // first 15 are 0
        for i in 0..15 {
            assert_eq!(got[i], U256::zero());
        }
        // last two are duplicated
        assert_eq!(got[15], U256::from(0xAA));
        assert_eq!(got[16], U256::from(0xAA));
    }

    #[test]
    fn apply_op_swap() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        ms.stack = vec![U256::one(), U256::from(0xAA)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SWAP1);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], U256::from(0xAA));
        assert_eq!(got[1], U256::one());

        ms.stack = vec![U256::one(); 17];
        ms.stack[16] = U256::from(0xAA);
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::SWAP16);
        assert_eq!(got.len(), 17);
        assert_eq!(got[0], U256::from(0xAA));
        assert_eq!(got[16], U256::one());
    }

    #[test]
    fn apply_op_log() {
        let (i, mut ms, mut s, mut a, headers) = init_context();

        // no substate to start with
        assert_eq!(a.len(), 0);

        // LOG 0
        ms.stack = vec![U256::from(0xffaa), U256::from(0xffff)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::LOG0);
        assert_eq!(got.len(), 0);

        // make sure a substate is appeneded
        assert_eq!(a.len(), 1);

        // LOG 4
        let (topic1, topic2, topic3, topic4) = (
            U256::from(0x1000),
            U256::from(0x1111),
            U256::from(0xABCD),
            U256::from(0x4321),
        );
        ms.stack = vec![
            U256::from(0xffaa),
            U256::from(0xffff),
            topic1,
            topic2,
            topic3,
            topic4,
        ];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::LOG4);
        assert_eq!(got.len(), 0);

        // make sure a substate is appeneded
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn apply_op_create() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();

        // 1 account
        let addr = H160::random();
        let mut account = Account::default();
        account.balance = U256::from(100);
        s.accounts.insert(addr, account);
        assert_eq!(s.accounts.len(), 1);
        // set this account as the caller
        i.a = addr;

        // CREATE - succeed: normal
        ms.stack = vec![U256::from(5), U256::from(0xffaa), U256::from(15000)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CREATE);
        assert_eq!(got.len(), 1);
        assert!(got[0] > U256::zero());

        // CREATE - failed: too much value
        ms.stack = vec![U256::from(500), U256::from(0xffaa), U256::from(15000)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CREATE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::zero());

        // CREATE - failed: too long initcode
        ms.stack = vec![U256::from(5), U256::from(0), U256::from(50000)];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CREATE);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::zero());
    }

    #[test]
    fn apply_op_call() {
        let (mut i, mut ms, mut s, mut a, headers) = init_context();

        // 2 accounts
        let alice = H160::random();
        let mut alice_account = Account::default();
        alice_account.balance = U256::from(100);
        s.accounts.insert(alice, alice_account);
        assert_eq!(s.accounts.len(), 1);

        let bob = H160::random();
        let mut bob_account = Account::default();
        bob_account.balance = U256::from(5);
        s.accounts.insert(bob, bob_account);
        assert_eq!(s.accounts.len(), 2);

        // set alice account as the caller
        i.s = alice;
        // i.v = U256::from(15);

        // Message-call for value transfer between EOA and EOA
        // instead of preparing a transaction as if end-user, we use OpCode::CALL
        // this tests `transitional` state

        // Message-Call
        // [gas, to, value, in offset, in size, out offset, out size]
        ms.stack = vec![
            U256::from(50),
            U256::from(bob.as_bytes()),
            U256::from(15),
            U256::from(0xaaaa),
            U256::from(64),
            U256::from(0xbbbb),
            U256::from(32),
        ];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CALL);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::one());

        // check for the correct deduction? or should it have any changes b/c this is EVM call?
        assert_eq!(s.accounts.len(), 2);
        // shadowing
        let alice_acc = s.accounts.get(&alice).unwrap();
        let bob_acc = s.accounts.get(&bob).unwrap();
        assert_eq!(alice_acc.balance, U256::from(85));
        assert_eq!(bob_acc.balance, U256::from(20));

        // Test phase 2: execution phase
        // need to store (KEC(b), b) pair aka. the code. we have just stored code directly
        // get alice account and store code
        let code = hex::decode("604260005260206000F3").unwrap();
        if let Some(alice_account) = s.accounts.get_mut(&alice) {
            alice_account.code = code;
        }

        // the same stack as above
        // it reads "read 64 bytes from memory at 0xaaaa"
        // for the output, use 32 bytes from memory at 0xbbbb"
        ms.stack = vec![
            U256::from(50),
            U256::from(bob.as_bytes()),
            U256::from(15),
            U256::from(0xaaaa),
            U256::from(64),
            U256::from(0xbbbb),
            U256::from(32),
        ];
        let (got, _, _) = apply_op(&headers, &mut s, &mut ms, &mut a, &i, OpCode::CALL);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], U256::one());
    }

    #[test]
    fn u8_from() {
        let number = u8::from(OpCode::PUSH1);
        assert_eq!(number, 0x60);
    }
}
