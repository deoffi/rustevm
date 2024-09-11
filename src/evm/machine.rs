use crate::evm::memory::Memory;
use primitive_types::{H160, U256};
use std::collections::HashMap;
use std::collections::HashSet;

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

pub type ResultantOutput = Vec<u8>;

// XXX: related to Ak in storage load and store. not sure what that is
#[derive(Debug, Clone)]
pub struct Substate {
    // selfdestruct set: a set of accounts to be  discarded following the tx's completion
    pub s: HashSet<H160>,
    // log series: "checkpoints" XXX: what do you mean?
    pub l: Vec<LogEntry>,
    // a set of touched accounts
    pub t: HashSet<H160>,
    // refund balance: increased when SSTORE is used to reset contract storage to zero from
    // non-zero value.
    pub r: U256,
    // a set of accessed account addresses(EIP-2929)
    pub a: HashSet<H160>,
    // a set of accessed storage keys where each element is (addr, 32-byte storage slot)
    pub k: HashMap<H160, U256>,
}

impl Default for Substate {
    fn default() -> Self {
        // aka pi
        let mut precompiled: HashSet<H160> = HashSet::new();
        precompiled.insert(H160::from_low_u64_be(1));
        precompiled.insert(H160::from_low_u64_be(2));
        precompiled.insert(H160::from_low_u64_be(3));
        precompiled.insert(H160::from_low_u64_be(4));
        precompiled.insert(H160::from_low_u64_be(5));
        precompiled.insert(H160::from_low_u64_be(6));
        precompiled.insert(H160::from_low_u64_be(7));
        precompiled.insert(H160::from_low_u64_be(8));
        precompiled.insert(H160::from_low_u64_be(9));

        Self {
            s: HashSet::new(),
            l: vec![],
            t: HashSet::new(),
            r: U256::zero(),
            a: precompiled,
            k: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub address: H160,
    pub topics: TopicSeries,
    pub content: Vec<u8>,
}

// the topic series could be a tuple from size 0 to 4
#[derive(Debug, Clone)]
pub enum TopicSeries {
    Empty(),
    One(U256),
    Two(U256, U256),
    Three(U256, U256, U256),
    Four(U256, U256, U256, U256),
}
