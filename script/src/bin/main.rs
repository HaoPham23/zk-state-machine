//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use state_machine_lib::{ElGamal, PublicParams, PublicValuesStruct, KZG, Action, Deposit};
use sp1_bls12_381::{G1Affine, Scalar};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const STATEMACHINE_ELF: &[u8] = include_elf!("state-machine-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    let mut pp = PublicParams::setup(16);
    let el_gamal = ElGamal::new(pp.g);
    let kzg = KZG::new(pp.g1_points.clone(), pp.g2_points.clone(), pp.g1_lagrange_basis.clone());
    let v = vec![Scalar::zero(); pp.degree];
    let mut phi = kzg.commit(v).unwrap();

    let sk_a = [1u64, 2, 3, 4];
    let pk_a = el_gamal.from_skey(sk_a);
    let sk_b = [5u64, 6, 7, 8];
    let pk_b = el_gamal.from_skey(sk_b);
    println!("User A's public key: {:?}", pk_a);
    println!("User B's public key: {:?}", pk_b);
    println!("User B's secret key: {:?}", sk_b);

    let (m_a, m_b) = (100u64, 200u64);    
    let (r_a, r_b) = ([0x1111u64, 0, 0, 0], [0x2222u64, 0, 0, 0]); // TODO: need random
    println!("User A generates random number r = {:?}", r_a);
    println!("User A deposits: {:?} ETH", m_a);
    println!("Update state...");

    let deposit_inputs = Deposit {
        pkey: pk_a,
        random: r_a,
        amount: m_a,
    };

    let action = Action::Deposit(deposit_inputs);

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&action);
    stdin.write(&phi);
    stdin.write(&pp);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(STATEMACHINE_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesStruct {old_phi, next_phi } = decoded;
        println!("old_phi: {:?}", G1Affine::from_compressed(&old_phi));
        println!("next_phi: {:?}", G1Affine::from_compressed(&next_phi));

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(STATEMACHINE_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
