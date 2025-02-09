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
use state_machine_lib::{PublicParams, PublicValuesDeposit, PublicValuesWithdraw, PublicValuesSend, PublicValuesRotate, Action, deposit, send, withdraw, rotate};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let action = sp1_zkvm::io::read::<Action>();
    let phi = sp1_zkvm::io::read::<G1Affine>();
    let mut pp = sp1_zkvm::io::read::<PublicParams>();

    let bytes = match action {
        Action::Deposit(deposit_inputs) => {
            // Handle deposit
            let next_phi = deposit(&mut pp, deposit_inputs.pkey, deposit_inputs.random, deposit_inputs.amount, phi).unwrap();
            PublicValuesDeposit::abi_encode(&PublicValuesDeposit {
                old_phi: phi.to_compressed(),
                next_phi: next_phi.to_compressed(),
                amount: alloy_sol_types::private::u256(deposit_inputs.amount),
                pkey: deposit_inputs.pkey.to_bytes(),
                v: pp.v[pp.idx - 1].to_bytes()
            })
        },
        Action::Send(send_inputs) => {
            // Handle send
            let next_phi = send(&mut pp, send_inputs.skey_sender, send_inputs.pkey_receiver, send_inputs.amount, phi).unwrap();
            PublicValuesSend::abi_encode(&PublicValuesSend {
                old_phi: phi.to_compressed(),
                next_phi: next_phi.to_compressed(),
            })
        },
        Action::Withdraw(withdraw_inputs) => {
            // Handle withdraw
            let next_phi = withdraw(&mut pp, withdraw_inputs.skey, withdraw_inputs.random, withdraw_inputs.amount, phi, withdraw_inputs.recipient).unwrap();
            PublicValuesWithdraw::abi_encode(&PublicValuesWithdraw {
                old_phi: phi.to_compressed(),
                next_phi: next_phi.to_compressed(),
                amount: alloy_sol_types::private::u256(withdraw_inputs.amount),
                recipient: alloy_sol_types::private::Address::from(withdraw_inputs.recipient)
            })
        },
        Action::Rotate(rotate_inputs)=> {
            // Handle rotate
            let next_phi = rotate(&mut pp, rotate_inputs.skey, rotate_inputs.new_additive, phi).unwrap();
            PublicValuesRotate::abi_encode(&PublicValuesRotate {
                old_phi: phi.to_compressed(),
                next_phi: next_phi.to_compressed(),
            })
        },
    };

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
