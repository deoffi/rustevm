use crate::memory::Memory;
use primitive_types::U256;

pub struct Context {
    address: String,
    balance: U256,
}

#[derive(Debug, Clone)]
pub struct SystemState {
    foo: String,
}

impl Default for SystemState {
    fn default() -> Self {
        Self {
            foo: "hello".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct G {
    remaining: U256,
}

impl Default for G {
    fn default() -> Self {
        Self {
            remaining: U256::from(25000),
        }
    }
}

#[derive(Debug)]
pub struct A {
    accrued: Vec<SubState>,
}

impl Default for A {
    fn default() -> Self {
        Self {
            accrued: vec![SubState {}],
        }
    }
}

pub type O = Vec<u8>;
//#[derive(Debug)]
//struct O {
//    value: String,
//}

#[derive(Debug)]
pub struct SubState {}

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub coinbase: U256,
    pub timestamp: U256,
    pub number: U256,
    pub prevrandao: U256,
    pub gaslimit: U256,
    pub chainid: U256,
    pub selfbalance: U256,
    pub basefee: U256,
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            coinbase: U256::from(0),
            timestamp: U256::from(0),
            number: U256::from(0),
            prevrandao: U256::from(0),
            gaslimit: U256::from(0),
            chainid: U256::from(0),
            selfbalance: U256::from(0),
            basefee: U256::from(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct I {
    // address of account that owns the code we are executing
    pub a: U256,
    // origin of this tx
    pub o: U256,
    // effective gas price
    pub p: U256,
    // byte array of input data. aka "tx data"
    // XXX: is there a maximum size of this? i know the minimum is 32 bytes.
    pub d: Vec<u8>,
    // address of account that caused this execution. aka msg.sender
    pub s: U256,
    // value in Wei
    pub v: U256,
    // byte array that is machine code to be executed
    pub b: Vec<u8>,
    // block header of the present block
    pub h: BlockHeader,
    // depth of the message-call
    pub e: U256,
    // permission to make modification to the state
    pub w: bool,
}

impl Default for I {
    fn default() -> Self {
        Self {
            a: U256::zero(),
            o: U256::zero(),
            p: U256::zero(),
            d: vec![],
            s: U256::zero(),
            v: U256::zero(),
            b: vec![],
            e: U256::zero(),
            h: BlockHeader::default(),
            w: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MachineState {
    // gas available
    pub gas_avail: U256,
    // program counter
    pub pc: U256,
    // series of zeroes in size 2^256
    // pub m: U256,
    pub m: Memory,
    // stack contents
    pub stack: Vec<U256>,
    // return data buffer
    pub returndata: String,
}

impl Default for MachineState {
    fn default() -> Self {
        Self {
            gas_avail: U256::zero(),
            pc: U256::zero(),
            m: Memory::default(),
            stack: vec![],
            returndata: String::default(),
        }
    }
}
