//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use alloy_sol_types::SolType;
use hex::decode;
use clap::{Parser, ValueEnum};
use state_machine_lib::{deposit, send, withdraw, PublicParams, PublicValuesRotate, KZG, ElGamal, Action, Rotate};
use sp1_bls12_381::Scalar;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const STATEMACHINE_ELF: &[u8] = include_elf!("state-machine-program");

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct EVMArgs {
    #[clap(long, default_value = "20")]
    n: u32,
    #[clap(long, value_enum, default_value = "groth16")]
    system: ProofSystem,
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1FibonacciProofFixture {
    a: u32,
    b: u32,
    n: u32,
    vkey: String,
    public_values: String,
    proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ProofRotateFixture {
    old_phi: String,
    next_phi: String,
    new_t: String,
    pkey: String,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = EVMArgs::parse();

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the program.
    let (pk, vk) = client.setup(STATEMACHINE_ELF);

    let mut pp = PublicParams::setup(16);
    let el_gamal = ElGamal::new(pp.g);
    let kzg = KZG::new(pp.g1_lagrange_basis.clone());
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
    let recipient = "65f697a02d756Cf4BC3465c1cC60dB3a4AF19521"; // TODO: need address
    let recipient: [u8; 20] = decode(recipient).unwrap().try_into().unwrap();
    phi = withdraw(&mut pp, sk_a, r_a, m_a, withdraw_amount, phi, recipient).unwrap();
    m_a -= withdraw_amount;

    let add_additive = [1u64, 0, 0, 0];
    let _new_r = [0x1112u64, 0, 0, 0]; // = r_a + add_additive
    println!("User A rotates his secret");
    println!("Update state...");

    let rotate_inputs = Rotate {
        skey: sk_a,
        new_additive: add_additive,
    };

    let action = Action::Rotate(rotate_inputs);

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&action);
    stdin.write(&phi);
    stdin.write(&pp);

    println!("Proof System: {:?}", args.system);

    let start = std::time::Instant::now();
    // Generate the proof based on the selected proof system.
    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, &stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, &stdin).groth16().run(),
    }
    .expect("failed to generate proof");
    println!("Proof generation time: {:?}", start.elapsed());

    let start = std::time::Instant::now();
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Proof verification time: {:?}", start.elapsed());

    create_proof_fixture(&proof, &vk, args.system);
}

/// Create a fixture for the given proof.
fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    system: ProofSystem,
) {
    // Deserialize the public values.
    let bytes = proof.public_values.as_slice();
    // Read the output.
    let decoded = PublicValuesRotate::abi_decode(bytes, true).unwrap();
    let PublicValuesRotate {
        old_phi, 
        next_phi,
        pkey,
        new_t} = decoded;
    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1ProofRotateFixture {
        old_phi: format!("0x{}", hex::encode(old_phi)),
        next_phi: format!("0x{}", hex::encode(next_phi)),
        pkey: format!("0x{}", hex::encode(pkey)),
        new_t: format!("0x{}", hex::encode(new_t)),
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values which are publicly committed to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    println!("Public Values: {}", fixture.public_values);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(format!("{:?}-zk-state-machine-fixture-rotate.json", system).to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
