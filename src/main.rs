use crate::evm::iterate::next_state;
use crate::evm::machine::{MachineState, Substate};
use crate::world::{BlockHeader, BlockHeaders, ExecutionEnvironment, SystemState};
use primitive_types::{H160, U256};

mod evm;
mod world;

// fix to read from the file
fn main() {
    println!("foo");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple() {
        let mut world_state = SystemState::default();
        let mut machine_state = MachineState::default();
        machine_state.gas_avail = U256::from(22000);
        let mut substates: Vec<Substate> = vec![];
        // execution environment
        // XXX: is it ethereum node that sets this up?
        let mut env = ExecutionEnvironment::default();

        // block
        let mut headers = BlockHeaders::default();
        let new_block = BlockHeader::default();
        headers.push(new_block);
        let next_block = U256::from(0);
        env.h = headers.get(next_block).unwrap();

        // set to false only when staticcal
        // i.w = false;

        // sender
        let alice = H160::random();
        env.o = alice;
        env.s = alice;

        // receiver
        let bob = H160::random();
        env.a = bob;
        let bytecode = hex::decode("604260005260206000F3").unwrap();
        env.b = bytecode;
        println!("env.b: {:?}", env.b);

        let (new_world_state, new_machine_state, new_substates, new_env, resultant_output) =
            next_state(
                &headers,
                &mut world_state,
                &mut machine_state,
                &mut substates,
                &env,
            );

        if let Some(output) = resultant_output {
            let output_u256 = U256::from(output.as_slice());
            assert_eq!(output_u256, U256::from(0x42));
        } else {
            assert!(false, "expected an output, but got nothing");
        }
    }
}
