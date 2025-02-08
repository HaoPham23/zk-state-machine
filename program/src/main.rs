//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use sp1_bls12_381::G1Affine;
use state_machine_lib::{PublicParams, PublicValuesStruct, Action, deposit, send, withdraw};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let action = sp1_zkvm::io::read::<Action>();
    let phi = sp1_zkvm::io::read::<G1Affine>();
    let mut pp = sp1_zkvm::io::read::<PublicParams>();
    let mut next_phi = phi;

    match action {
        Action::Deposit(deposit_inputs) => {
            // Handle deposit
            next_phi = deposit(&mut pp, deposit_inputs.pkey, deposit_inputs.random, deposit_inputs.amount, phi).unwrap();
        },
        Action::Send(send_inputs) => {
            // Handle send
            next_phi = send(&mut pp, send_inputs.skey_sender, send_inputs.pkey_receiver, send_inputs.amount, phi).unwrap();
        },
        Action::Withdraw(withdraw_inputs) => {
            // Handle withdraw
            next_phi = withdraw(&mut pp, withdraw_inputs.skey, withdraw_inputs.random, withdraw_inputs.amount, phi, withdraw_inputs.recipient).unwrap();
        },
        Action::Rotate { new_key } => {
            // Handle rotate
            // panic!("Rotate not implemented");
        },
    }

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        old_phi: phi.to_compressed(),
        next_phi: next_phi.to_compressed() 
    });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
