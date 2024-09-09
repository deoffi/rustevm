use crate::memory::Memory;
use primitive_types::{H160, H256, U256};
use std::collections::HashMap;
use std::collections::VecDeque;

pub struct Context {
    address: String,
    balance: U256,
}

#[derive(Debug, Clone)]
pub struct SystemState {
    pub accounts: HashMap<H160, Account>,
}

impl Default for SystemState {
    fn default() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Account {
    pub nonce: U256,
    pub balance: U256,
    // XXX: this should represent a 256-bit hash to Merkle Patricia tree root node which acts as a
    // mapping between two 256-bit integers. For the sake of simplicity, however, the map is
    // initialized and used here.
    pub storage_root: HashMap<U256, U256>,
    // XXX: should be code_hash that is a key to full code on another database.
    //      for simplicity of EVM, use code directly.
    // pub code_hash: H256,
    pub code: Vec<u8>,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            nonce: U256::zero(),
            balance: U256::zero(),
            storage_root: HashMap::new(),
            code: vec![],
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
    pub accrued: Vec<SubState>,
}

impl Default for A {
    fn default() -> Self {
        Self { accrued: vec![] }
    }
}

pub type O = Vec<u8>;
//#[derive(Debug)]
//struct O {
//    value: String,
//}

// XXX: related to Ak in storage load and store. not sure what that is
#[derive(Debug)]
pub struct SubState {
    // log series
    pub l: Vec<LogEntry>,
}

impl Default for SubState {
    fn default() -> Self {
        Self { l: vec![] }
    }
}

#[derive(Debug)]
pub struct LogEntry {
    pub address: H160,
    pub topics: TopicSeries,
    pub content: Vec<u8>,
}

// the topic series could be a tuple from size 0 to 4
#[derive(Debug)]
pub enum TopicSeries {
    Empty(),
    One(U256),
    Two(U256, U256),
    Three(U256, U256, U256),
    Four(U256, U256, U256, U256),
}

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub blockhash: H256,
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
            blockhash: H256::zero(),
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

// this is  another environment like SystemState
#[derive(Debug)]
pub struct BlockHeaders {
    headers: VecDeque<BlockHeader>,
    size: U256,
}
impl Default for BlockHeaders {
    fn default() -> Self {
        Self {
            headers: VecDeque::new(),
            size: U256::zero(),
        }
    }
}
impl BlockHeaders {
    pub fn push(&mut self, header: BlockHeader) {
        if self.size > U256::MAX {
            self.headers.pop_front();
            self.size -= U256::one();
        }
        self.headers.push_back(header);
        self.size += U256::one();
    }

    pub fn get(&self, number: U256) -> Option<BlockHeader> {
        // fit into 256
        let n = number % 256;
        let idx = n.low_u32() as usize;
        if let Some(header) = self.headers.get(idx) {
            Some(header.clone())
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct I {
    // address of account that owns the code we are executing
    pub a: H160,
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
            a: H160::random(),
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

mod tests {
    use super::*;

    #[test]
    fn blockheaders_get() {
        let mut headers = BlockHeaders::default();
        let mut hashes = vec![];
        let mut first_hash = H256::zero();
        let mut last_hash = H256::zero();
        for i in 0..256 {
            let mut h = BlockHeader::default();
            h.number = U256::from(i);
            let hash = H256::random();
            hashes.push(hash);
            h.blockhash = hash;
            headers.push(h);
            if i == 0 {
                first_hash = hash;
            }
            if i == 255 {
                last_hash = hash;
            }
        }

        let h1 = headers.get(U256::zero()).unwrap();
        let h2 = headers.get(U256::zero()).unwrap();
        assert_eq!(h1.blockhash, h2.blockhash);

        let h = headers.get(U256::zero()).unwrap();
        assert_eq!(h.blockhash, first_hash);

        let h = headers.get(U256::from(255)).unwrap();
        assert_eq!(h.blockhash, last_hash);
    }
}
