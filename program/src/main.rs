//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, PublicValuesStruct};
use sp1_bls12_381::Scalar;

fn deposit(pp: PublicParams, pk_a: Scalar, r_a: [u64; 4], m_a: u64 , phi: G1Affine) -> G1Affine {
    unsafe {
        let el_gamal = ElGamal::new(pp.r, pp.g);
        let (t, v) = el_gamal.encrypt(pk_a, m_a, r_a);
        let e = G1Affine::from(v * pp.g1_lagrange_basis[idx]);
        let next_phi = phi.add_affine(&e);
        idx += 1;
        next_phi
    }
}

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let option = sp1_zkvm::io::read::<u32>();
    let publicKey = sp1_zkvm::io::read::<u32>();

    // Compute the n'th fibonacci number using a function from the workspace lib crate.
    let (a, b) = fibonacci(n);

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { n, a, b });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
