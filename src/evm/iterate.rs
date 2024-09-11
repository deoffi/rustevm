use crate::evm::machine::{MachineState, ResultantOutput, Substate};
use crate::evm::opcode::{apply_op, OpCode};
use crate::evm::utils::vec8_to_u256;
use crate::world::{BlockHeaders, ExecutionEnvironment, SystemState};
use primitive_types::U256;
use std::collections::HashSet;

// aka X(s, ms, a, i)
//      for our case, we need another env var `headers`
//  ResultantOoutput(aka O): the resultant output is from H.
pub fn next_state(
    headers: &BlockHeaders,
    world_state: &mut SystemState,
    machine_state: &mut MachineState,
    substates: &mut Vec<Substate>,
    env: &ExecutionEnvironment,
) -> (
    SystemState,
    MachineState,
    Vec<Substate>,
    ExecutionEnvironment,
    Option<ResultantOutput>,
) {
    println!("stack: {:?}", machine_state.stack);
    // is there an exceptional halt?
    if is_exceptional_halt(machine_state, world_state, substates, env) {
        // return (empty set, ms, a, i, empty set)
        let empty_system_state = SystemState::default();
        // must be an emtpy set instead of an empty sequnce
        let resultant_output = None;
        return (
            empty_system_state,
            machine_state.clone(),
            substates.clone(),
            env.clone(),
            resultant_output,
        );
    } else {
        // is there a normal halt?
        let (mut world_state_p, mut machine_state_p, mut substates_p, env_p) =
            execute(&headers, world_state, machine_state.clone(), substates, env);
        println!("executed");

        match normal_halt(machine_state, env) {
            Some(seq) => {
                println!("- - - returning!");
                return (
                    world_state_p,
                    machine_state_p,
                    substates_p,
                    env_p,
                    Some(seq),
                );
            }
            None => {
                println!("- - - continue");
                // continue
                // next iteration should be X(O(s, ms, A, I))
                return next_state(
                    &headers,
                    &mut world_state_p,
                    &mut machine_state_p,
                    &mut substates_p,
                    &env_p,
                );
            }
        }
    }
}

// the current operation to be executed: aka "w"
fn next_op(machine_state: &MachineState, env: &ExecutionEnvironment) -> OpCode {
    let size = U256::from_dec_str(&format!("{}", env.b.len())).unwrap();
    if machine_state.pc < size {
        // read the next byte
        // U256 to usize?
        let idx: usize = machine_state.pc.as_u64().try_into().unwrap();
        return OpCode::from(env.b[idx]);
    }
    return OpCode::STOP;
}

// exception handling. aka Z(s, ms, a, i)
// NOTE: no instruction can cause an exception through its execution.
fn is_exceptional_halt(
    ms: &MachineState,
    s: &SystemState,
    a: &Vec<Substate>,
    i: &ExecutionEnvironment,
) -> bool {
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
    if i.w == false && is_modifying(op.clone(), ms) {
        return true;
    }
    if op == OpCode::SSTORE {
        // ms.gas_avail <= G callstipend. ref. EIP-2200
    }

    return false;
}

fn compute_gas(
    s: &SystemState,
    ms: &MachineState,
    a: &Vec<Substate>,
    i: &ExecutionEnvironment,
) -> U256 {
    U256::from(0)
}

// aka W(w, u)
// this determines whether the operation is making changes to the state or not.
fn is_modifying(code: OpCode, ms: &MachineState) -> bool {
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
fn normal_halt(
    machine_state: &mut MachineState,
    env: &ExecutionEnvironment,
) -> Option<ResultantOutput> {
    let op = next_op(&machine_state, env);
    println!("normal_halt: {:?}", op);

    if op == OpCode::RETURN || op == OpCode::REVERT {
        // data-returning operation!
        // TODO:
        // Hreturn(ms) = ms.m[ms.stack[0] ... ms.stack[1] - 1]

        // for gas calculations, use memory expansion function: ms'.i = M(ms.i, ms.stack[0], ms.stack[1])
        // ms.i is the maximum number of words of active memory

        println!("[normal_halt]: {:?}", machine_state.stack);

        // return what we have in memory
        // [32, 0]
        // [size, offset]
        let a = machine_state.stack.pop().unwrap();
        let b = machine_state.stack.pop().unwrap();

        let offset = a.low_u32() as usize;
        let size = b.low_u32() as usize;

        let data = machine_state.m.load(offset, size);

        // let headers = BlockHeaders::default();
        // let mut world_state = SystemState::default();
        // let mut substates: Vec<Substate> = vec![];
        // let (mut result_stack, ac, rc) = apply_op(
        //     &headers,
        //     &mut world_state,
        //     machine_state,
        //     &mut substates,
        //     env,
        //     op,
        // );
        //
        // // assuming inferred conversion here from U256 to bytes
        // let output: U256 = result_stack.pop().unwrap();
        return Some(data);
    }

    if op == OpCode::STOP || op == OpCode::SELFDESTRUCT {
        // return empty sequence: ()
        // denotes that execution should halt
        return Some(vec![]);
    }

    // return empty set: {}
    // denotes that execution should continue
    return None;
}

// stack items are added or removed from the left-most, lower-indexed portion of the series.
// XXX: what does the above line mean?
// in general, we don't assume the memory, accrued substate, and system state do not change.
// however, instruction do alter one or several components of this
// defines a single cycle of the state machine. aka O(s, ms, a, i)
fn execute(
    headers: &BlockHeaders,
    mut world_state: &mut SystemState,
    mut machine_state: MachineState,
    mut substates: &mut Vec<Substate>,
    env: &ExecutionEnvironment,
) -> (
    SystemState,
    MachineState,
    Vec<Substate>,
    ExecutionEnvironment,
) {
    let op = next_op(&machine_state, env);
    println!("execute: {:?}", op);

    // update stack
    let prev_size = U256::from_dec_str(&format!("{}", machine_state.stack.len())).unwrap();
    let (result_stack, ac, rc) = apply_op(
        &headers,
        &mut world_state,
        &mut machine_state,
        &mut substates,
        env,
        op,
    );
    println!("done with apply_op of: {:?}", op);
    let new_size = U256::from_dec_str(&format!("{}", result_stack.len())).unwrap();
    if ac > rc {
        let delta = ac - rc;
        assert!(
            new_size == (prev_size + delta),
            "stack lengths do not match"
        );
    } else {
        let delta = rc - ac;
        assert!(
            new_size == (prev_size - delta),
            "stack lengths do not match"
        );
    }

    machine_state.stack = result_stack;
    println!("stack updated");

    // update gas available
    machine_state.gas_avail =
        machine_state.gas_avail - compute_gas(world_state, &machine_state, substates, env);
    println!("gas_avail updated");

    // update pc
    if op == OpCode::JUMP {
        machine_state.pc = jump(&machine_state);
    } else if op == OpCode::JUMPI {
        machine_state.pc = jumpi(&machine_state);
    } else {
        machine_state.pc = next_valid_i_pos(machine_state.pc, op);
    }
    println!("new PC: {:?}", machine_state.pc);
    println!("memory: {:?}", machine_state.m);

    return (
        world_state.clone(),
        machine_state.clone(),
        substates.clone(),
        env.clone(),
    );
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
