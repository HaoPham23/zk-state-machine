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
use hex::decode;
use clap::Parser;
use state_machine_lib::{deposit, send, Action, ElGamal, PublicParams, PublicValuesWithdraw, Withdraw, KZG};
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

    let (mut m_a, mut m_b) = (100u64, 200u64);    
    let (r_a, r_b) = ([0x1111u64, 0, 0, 0], [0x2222u64, 0, 0, 0]); // TODO: need random
    println!("User A generates random number r = {:?}", r_a);
    println!("User A deposits: {:?} ETH", m_a);
    println!("Update state...");

    phi = deposit(&mut pp, pk_a, r_a, m_a, phi).unwrap();

    println!("User B deposits: {:?} ETH", m_b);
    println!("Update state...");

    phi = deposit(&mut pp, pk_b, r_b, m_b, phi).unwrap();

    let amount = 30u64;
    println!("User B sends {:?} ETH to User A", amount);
    println!("Update state...");

    phi = send(&mut pp, sk_b, pk_a, m_b, amount, phi).unwrap();
    m_b -= amount;
    m_a += amount;

    let withdraw_amount = 10u64;

    println!("User A withdraws {:?} ETH", withdraw_amount);
    println!("Update state...");

    // private key: 0xc0cf034c2039fbb095aad1cd7dfd8854eddc5fcfed04e009520049107022b22b
    let A = "65f697a02d756Cf4BC3465c1cC60dB3a4AF19521"; // TODO: need address
    let A: [u8; 20] = decode(A).unwrap().try_into().unwrap();
    let withdraw_inputs = Withdraw {
        balance: m_a,
        amount: withdraw_amount,
        random: r_a,
        skey: sk_a,
        recipient: A,
    };

    let action = Action::Withdraw(withdraw_inputs);

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&action);
    stdin.write(&phi);
    stdin.write(&pp);

    if args.execute {
        // Execute the program
        let start = std::time::Instant::now();
        let (output, report) = client.execute(STATEMACHINE_ELF, &stdin).run().unwrap();
        println!("Execution time: {:?}", start.elapsed());
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesWithdraw::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesWithdraw {
            old_phi, 
            next_phi, 
            amount,
            recipient
            } = decoded;
        println!("old_phi: {:?}", old_phi);
        println!("next_phi: {:?}", next_phi);

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
