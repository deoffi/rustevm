use crate::context::{MachineState, SystemState, A, G, I, O};
use crate::opcode::{apply_op, OpCode};
use primitive_types::U256;
use std::collections::HashSet;
use std::fmt;

mod context;
mod memory;
mod opcode;
mod signed;

#[derive(Debug, Clone)]
struct HaltError;

impl fmt::Display for HaltError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "execution came to a normal halt")
    }
}

fn main() {
    // stack
    let mut stack: Vec<U256> = vec![];
    let lo = U256::from_dec_str("0").expect("cannot create min U256 value");
    let hi = U256::from_dec_str(
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    )
    .expect("cannot create max U256 value");
    stack.push(lo);
    stack.push(hi);

    println!("hi > low: {}", stack.pop() > stack.pop());

    let s = SystemState::default();
    let g = G::default();
    let a = A::default();
    let i = I::default();

    let (s_p, g_p, a_p, o_p) = f(stack, s, g, a, i);

    println!("world state: {s_p:?}");
    println!("remaining gas: {g_p:?}");
    println!("substates: {a_p:?}");
    println!("output: {o_p:?}");

    println!("done");
}

fn f(stack: Vec<U256>, s: SystemState, g: G, a: A, i: I) -> (SystemState, G, A, O) {
    let s_prime = SystemState::default();
    let g_prime = G::default();
    let a_prime = A::default();
    let o_prime = vec![];

    return (s_prime, g_prime, a_prime, o_prime);
}

// aka X(s, ms, a, i)
fn iterate(
    s: &SystemState,
    ms: &MachineState,
    a: &A,
    i: &I,
) -> (SystemState, MachineState, A, I, O) {
    if is_exceptional_halt(ms, s, a, i) {
        // return (empty set, ms, a, i, empty set)
    }

    let op = next_op(ms, i);
    if op == OpCode::REVERT {
        // return (empty set, ms', a, i, o)
    }

    let (s_p, ms_p, a_p, i_p) = execute(s, ms.clone(), a, i);
    match normal_halt(ms, i) {
        Ok(seq) => return (s_p, ms_p, a_p, i_p, seq),
        Err(err) => {
            // return halt error?
        }
    }

    // next iteration
    return iterate(&s_p, &ms_p, &a_p, &i_p);
}

// the current operation to be executed: aka "w"
fn next_op(ms: &MachineState, i: &I) -> OpCode {
    let size = U256::from_dec_str(&format!("{}", i.b.len())).unwrap();
    if ms.pc < size {
        // read the next byte
        // U256 to usize?
        let idx: usize = ms.pc.as_u64().try_into().unwrap();
        return OpCode::from(i.b[idx]);
    }
    return OpCode::STOP;
}

// exception handling. aka Z(s, ms, a, i)
// NOTE: no instruction can cause an exception through its execution.
fn is_exceptional_halt(ms: &MachineState, s: &SystemState, a: &A, i: &I) -> bool {
    // insufficient gas
    if ms.gas_avail < compute_gas(s, ms, a, i) {
        println!("not enough gas!");
        return true;
    }

    // invalid instruction

    // insufficient stack items

    let op = next_op(ms, i);

    // JUMP/JUMPI destination is invalid
    if op == OpCode::JUMP {
        let pos = ms.stack[0];
        let valid_pos = valid_jump_dests(i.b.clone(), U256::zero());
        if valid_pos.contains(&pos) == false {
            // stack at 0 is NOT included in valid positions set
            // exceptional halt
            return true;
        }
    }
    if op == OpCode::JUMPI {
        let pos = ms.stack[1];
        if pos != U256::zero() {
            let pos = ms.stack[0];
            let valid_pos = valid_jump_dests(i.b.clone(), U256::zero());
            if valid_pos.contains(&pos) == false {
                // stack at 0 is NOT included in valid positions set
                // exceptional halt
                return true;
            }
        }
    }

    if op == OpCode::RETURNDATACOPY {
        // greater than returndata buffer length
        if (ms.stack[1] + ms.stack[2]) > U256::from(ms.returndata.len()) {
            return true;
        }
    }
    // the new stack size > 1024
    // rc: stack items removed
    // ac: stack items added
    /*

         > We also assume the fixed amounts of δ and α, specifying
    the stack items removed and added, both subscriptable
    on the instruction and an instruction cost function C eval-
    uating to the full cost, in gas, of executing the given
    instruction.

    */
    // XXX:
    //if (ms.stack.len() - rc + ac) > 1024 {
    //    return true;
    //}

    // state modification is attempted during STAICCALL
    if i.w == false && W(op.clone(), ms) {
        return true;
    }
    if op == OpCode::SSTORE {
        // ms.gas_avail <= G callstipend. ref. EIP-2200
    }

    return false;
}

fn compute_gas(s: &SystemState, ms: &MachineState, a: &A, i: &I) -> U256 {
    return U256::from_dec_str("21000").expect("cannot create U256");
}

fn W(code: OpCode, ms: &MachineState) -> bool {
    if code == OpCode::CREATE
        || code == OpCode::CREATE2
        || code == OpCode::SSTORE
        || code == OpCode::SELFDESTRUCT
    {
        return true;
    }

    if OpCode::LOG0 <= code && code <= OpCode::LOG4 {
        return true;
    }

    if code == OpCode::CALL && ms.stack[2] != U256::zero() {
        return true;
    }

    return false;
}

// XXX: not sure how "empty sequence" should differ from "empty set"?
//      can we just "halt" vs "not halt"?
// returns "o" - resultant output
// aka H(ms, i)
fn normal_halt(ms: &MachineState, i: &I) -> Result<Vec<u8>, HaltError> {
    let op = next_op(ms, i);

    if op == OpCode::RETURN || op == OpCode::REVERT {
        // data-returning operation!
        // TODO:
        // Hreturn(ms) = ms.m[ms.stack[0] ... ms.stack[1] - 1]

        // for gas calculations, use memory expansion function: ms'.i = M(ms.i, ms.stack[0], ms.stack[1])
        // ms.i is the maximum number of words of active memory
    }

    if op == OpCode::STOP || op == OpCode::SELFDESTRUCT {
        // return empty sequence: ()
        // denotes that execution should halt
        return Err(HaltError);
    }

    // return empty set: {}
    // denotes that execution should continue
    return Ok(vec![]);
}

// stack items are added or removed from the left-most, lower-indexed portion of the series.
// XXX: what does the above line mean?
// in general, we don't assume the memory, accrued substate, and system state do not change.
// however, instruction do alter one or several components of this
// defines a single cycle of the state machine. aka O(s, ms, a, i)
fn execute(
    s: &SystemState,
    mut ms: MachineState,
    a: &A,
    i: &I,
) -> (SystemState, MachineState, A, I) {
    let op = next_op(&ms, i);

    // update stack
    let (result_stack, ac, rc) = apply_op(ms.stack.clone(), i, &mut ms, op);
    let delta = ac - rc;
    let prev_size = U256::from_dec_str(&format!("{}", ms.stack.len())).unwrap();
    let new_size = U256::from_dec_str(&format!("{}", result_stack.len())).unwrap();
    assert!(
        new_size == (prev_size + delta),
        "stack lengths do not match"
    );
    ms.stack = result_stack;

    // update gas available
    ms.gas_avail = ms.gas_avail - compute_gas(s, &ms, a, i);

    // update pc
    if op == OpCode::JUMP {
        ms.pc = jump(&ms);
    } else if op == OpCode::JUMPI {
        ms.pc = jumpi(&ms);
    } else {
        ms.pc = next_valid_i_pos(ms.pc, op);
    }

    let s_p = SystemState::default();
    let ms_p = MachineState::default();
    let a_p = A::default();

    return (s_p, ms_p, a_p, i.clone());
}

fn jump(ms: &MachineState) -> U256 {
    // TODO:
    return U256::zero();
}

fn jumpi(ms: &MachineState) -> U256 {
    // TODO:
    return U256::zero();
}

// jump destination validity. aka Dj(c,0)
fn valid_jump_dests(code: Vec<u8>, index: U256) -> HashSet<U256> {
    let mut positions = HashSet::new();

    // empty set if all code is read
    if index >= U256::from(code.len()) {
        return positions;
    }

    // union set of current position and the next position
    let idx: usize = index.as_u64().try_into().unwrap();
    if OpCode::from(code[idx]) == OpCode::JUMPDEST {
        let idx_u256 = U256::from(idx);
        positions.insert(idx_u256);
        let pos = next_valid_i_pos(idx_u256, OpCode::from(code[idx]));
        positions.insert(pos);
        return positions;
    }

    // a set of next position
    let idx_u256 = U256::from(idx);
    let pos = next_valid_i_pos(idx_u256, OpCode::from(code[idx]));
    positions.insert(pos);
    return positions;
}

// next valid instruction position. aka N(i,w)
// next valid position in the code
fn next_valid_i_pos(idx: U256, op: OpCode) -> U256 {
    // if op is in range of PUSH1 and PUSH32
    if OpCode::PUSH1 <= op && op <= OpCode::PUSH32 {
        let push1_u256 = U256::from(u8::from(OpCode::PUSH1));
        let op_u256 = U256::from(u8::from(op));
        idx + op_u256 - push1_u256 + U256::from(2)
    } else {
        idx + U256::one()
    }
}
