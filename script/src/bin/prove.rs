//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be verified
//! on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --package fibonacci-script --bin prove --release
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use hex;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    HashableKey, ProverClient, SP1CompressedProof, SP1PlonkBn254Proof, SP1ProvingKey, SP1PublicValues, SP1Stdin,
    SP1VerifyingKey,
};
use std::fs;
use std::path::PathBuf;

use sp1_lido_accounting_zk_shared::{
    beacon_state_reader::{BeaconStateReader, FileBasedBeaconStateReader},
    eth_consensus_layer::BeaconStatePrecomputedHashes,
    program_io::{ProgramInput, PublicValuesRust, PublicValuesSolidity},
};

use sp1_lido_accounting_zk_shared::verification::{FieldProof, MerkleTreeFieldLeaves};

use anyhow::Result;
use log;

use dotenv::dotenv;
use std::env;

use tree_hash::TreeHash;

const ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the prove command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value = "false")]
    evm: bool,
    #[clap(long)]
    path: PathBuf,
}

trait ScriptSteps<ProofType> {
    fn prove(&self, input: SP1Stdin) -> Result<ProofType>;
    fn verify(&self, proof: &ProofType) -> Result<()>;
    fn extract_public_values<'a>(&self, proof: &'a ProofType) -> &'a SP1PublicValues;
    fn post_verify(&self, proof: &ProofType);
}

struct EvmScript {
    client: ProverClient,
    pk: SP1ProvingKey,
    vk: SP1VerifyingKey,
}

impl EvmScript {
    fn new(elf: &[u8]) -> Self {
        let client: ProverClient = ProverClient::network();
        let (pk, vk) = client.setup(elf);
        Self { client, pk, vk }
    }
}

impl ScriptSteps<SP1PlonkBn254Proof> for EvmScript {
    fn prove(&self, input: SP1Stdin) -> Result<SP1PlonkBn254Proof> {
        self.client.prove_plonk(&self.pk, input)
    }

    fn verify(&self, proof: &SP1PlonkBn254Proof) -> Result<()> {
        self.client.verify_plonk(proof, &self.vk)
    }

    fn extract_public_values<'a>(&self, proof: &'a SP1PlonkBn254Proof) -> &'a SP1PublicValues {
        &proof.public_values
    }

    fn post_verify(&self, proof: &SP1PlonkBn254Proof) {
        create_plonk_fixture(proof, &self.vk);
    }
}

struct LocalScript {
    client: ProverClient,
    pk: SP1ProvingKey,
    vk: SP1VerifyingKey,
}

impl LocalScript {
    fn new(elf: &[u8]) -> Self {
        let client: ProverClient = ProverClient::local();
        let (pk, vk) = client.setup(elf);
        Self { client, pk, vk }
    }
}

impl ScriptSteps<SP1CompressedProof> for LocalScript {
    fn prove(&self, input: SP1Stdin) -> Result<SP1CompressedProof> {
        self.client.prove_compressed(&self.pk, input)
    }

    fn verify(&self, proof: &SP1CompressedProof) -> Result<()> {
        self.client.verify_compressed(proof, &self.vk)
    }

    fn extract_public_values<'a>(&self, proof: &'a SP1CompressedProof) -> &'a SP1PublicValues {
        &proof.public_values
    }

    fn post_verify(&self, _proof: &SP1CompressedProof) {}
}

fn run_script<ProofType>(
    steps: impl ScriptSteps<ProofType>,
    program_input: &ProgramInput,
    expected_public_values: &PublicValuesRust,
) {
    let mut stdin: SP1Stdin = SP1Stdin::new();
    stdin.write(&program_input);

    let proof = steps.prove(stdin).expect("failed to generate proof");
    log::info!("Successfully generated proof!");
    steps.verify(&proof).expect("failed to verify proof");
    log::info!("Successfully verified proof!");

    // let public_values_bytes = PublicValuesSolidity::abi_decode(proof.public_values.as_slice(), false)?
    let public_values_bytes = steps.extract_public_values(&proof);
    let public_values: PublicValuesRust = public_values_bytes
        .as_slice()
        .try_into()
        .expect("Failed to parse public values");

    assert!(public_values == *expected_public_values);
    log::debug!(
        "Expected hash: {}",
        hex::encode(expected_public_values.beacon_block_hash)
    );
    log::debug!("Computed hash: {}", hex::encode(public_values.beacon_block_hash));

    log::info!("Public values match!");
    steps.post_verify(&proof);
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = ProveArgs::parse();

    println!("evm: {}", args.evm);

    let file_path = fs::canonicalize(args.path).expect("Couldn't canonicalize path");
    let bs_reader = FileBasedBeaconStateReader::new(file_path);
    let bs = bs_reader
        .read_beacon_state(0) // slot is ignored; TODO: refactor readers
        .await
        .expect("Failed to read beacon state");

    let slot = bs.slot;
    let beacon_block_hash = bs.tree_hash_root();

    let bs_with_precomputed: BeaconStatePrecomputedHashes = (&bs).into();
    let indices = bs
        .get_leafs_indices(["validators", "balances"])
        .expect("Failed to get leaf indices");

    let validators_and_balances_proof: Vec<u8> = bs.get_serialized_multiproof(&indices);

    let program_input = ProgramInput {
        slot,
        beacon_block_hash: beacon_block_hash.to_fixed_bytes(),
        beacon_state: bs_with_precomputed,
        validators_and_balances_proof: validators_and_balances_proof,
    };
    let expected_public_values = PublicValuesRust {
        slot,
        beacon_block_hash: beacon_block_hash.to_fixed_bytes(),
    };

    if args.evm {
        run_script(EvmScript::new(ELF), &program_input, &expected_public_values);
    } else {
        run_script(LocalScript::new(ELF), &program_input, &expected_public_values);
    }
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofFixture {
    slot: u64,
    beacon_block_hash: String,
    vkey: String,
    public_values: String,
    proof: String,
}

/// Create a fixture for the given proof.
fn create_plonk_fixture(proof: &SP1PlonkBn254Proof, vk: &SP1VerifyingKey) {
    // Deserialize the public values.
    let bytes = proof.public_values.as_slice();
    let (slot, beacon_block_hash) = PublicValuesSolidity::abi_decode(bytes, false).unwrap();

    // Create the testing fixture so we can test things end-ot-end.
    let fixture = ProofFixture {
        slot: slot,
        beacon_block_hash: beacon_block_hash.to_string(),
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof.bytes().to_string(),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values whicha are publically commited to by the zkVM.
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
        fixture_path.join("fixture.json"),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
