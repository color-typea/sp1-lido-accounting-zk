use hex::FromHex;
use log;
use serde_json::Value;

use sp1_lido_accounting_zk_shared::consts::LIDO_WITHDRAWAL_CREDENTIALS;
use sp1_lido_accounting_zk_shared::lido::LidoValidatorState;
use std::collections::HashSet;
use std::path::PathBuf;
use tree_hash::TreeHash;
use util::synthetic_beacon_state_reader::GenerationSpec;

use sp1_lido_accounting_zk_shared::beacon_state_reader::synthetic_beacon_state_reader::{
    BalanceGenerationMode, SyntheticBeaconStateCreator,
};
use sp1_lido_accounting_zk_shared::beacon_state_reader::{BeaconStateReader, FileBasedBeaconStateReader};
use sp1_lido_accounting_zk_shared::eth_consensus_layer::{epoch, BeaconState, Hash256};
use sp1_lido_accounting_zk_shared::util::usize_to_u64;

use simple_logger::SimpleLogger;

fn hex_str_to_h256(hex_str: &str) -> Hash256 {
    <[u8; 32]>::from_hex(hex_str)
        .expect("Couldn't parse hex_str as H256")
        .into()
}

fn verify_state(beacon_state: &BeaconState, state: &LidoValidatorState, manifesto: &Value) {
    assert_eq!(state.slot, manifesto["report"]["slot"].as_u64().unwrap());
    assert_eq!(state.epoch, manifesto["report"]["epoch"].as_u64().unwrap());
    assert_eq!(
        usize_to_u64(state.deposited_lido_validator_indices.len()),
        manifesto["report"]["lido_deposited_validators"].as_u64().unwrap()
    );
    assert_eq!(
        usize_to_u64(state.exited_lido_validator_indices.len()),
        manifesto["report"]["lido_exited_validators"].as_u64().unwrap()
    );
    assert_eq!(
        usize_to_u64(state.future_deposit_lido_validator_indices.len()),
        manifesto["report"]["lido_future_deposit_validators"].as_u64().unwrap()
    );
    assert_eq!(
        state.max_validator_index,
        manifesto["report"]["total_validators"].as_u64().unwrap() - 1
    );

    let epoch = epoch(beacon_state.slot).unwrap();
    let withdrawal_creds: Hash256 = LIDO_WITHDRAWAL_CREDENTIALS.into();

    let deposited_hash_set: HashSet<u64> = HashSet::from_iter(state.deposited_lido_validator_indices.clone());
    let future_deposit_hash_set: HashSet<u64> = HashSet::from_iter(state.future_deposit_lido_validator_indices.clone());
    let exited_hash_set: HashSet<u64> = HashSet::from_iter(state.exited_lido_validator_indices.clone());

    for (idx, validator) in beacon_state.validators.iter().enumerate() {
        let validator_index = usize_to_u64(idx);

        if validator.withdrawal_credentials != withdrawal_creds {
            assert!(!deposited_hash_set.contains(&validator_index));
            assert!(!future_deposit_hash_set.contains(&validator_index));
            assert!(!exited_hash_set.contains(&validator_index));
        } else {
            if epoch >= validator.activation_eligibility_epoch {
                assert!(deposited_hash_set.contains(&validator_index));
            } else {
                assert!(future_deposit_hash_set.contains(&validator_index));
            }

            if epoch >= validator.exit_epoch {
                assert!(exited_hash_set.contains(&validator_index));
            }
        }
    }
}

#[tokio::main]
async fn main() {
    SimpleLogger::new().env().init().unwrap();
    let ssz_folder = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../temp");
    let creator = SyntheticBeaconStateCreator::new(&ssz_folder, false, true);
    let reader = FileBasedBeaconStateReader::new(&ssz_folder);

    // Step 1. obtain SSZ-serialized beacon state
    let slot = 123456;
    let generation_spec = GenerationSpec {
        slot: slot,
        non_lido_validators: 2_u64.pow(7),
        deposited_lido_validators: 2_u64.pow(6),
        exited_lido_validators: 4,
        future_deposit_lido_validators: 8,
        balances_generation_mode: BalanceGenerationMode::FIXED,
        shuffle: true,
        base_slot: None,
        overwrite: true,
    };
    creator
        .create_beacon_state(generation_spec)
        .await
        .expect("Failed to create beacon state");
    let beacon_state = reader
        .read_beacon_state(slot)
        .await
        .expect("Failed to read beacon state");
    log::info!(
        "Read Beacon State for slot {:?}, with {} validators",
        beacon_state.slot,
        beacon_state.validators.to_vec().len(),
    );

    // Step 2: read manifesto
    let manifesto = creator
        .read_manifesto(slot)
        .await
        .expect("Failed to read manifesto json");
    let lido_withdrawal_creds = hex_str_to_h256(manifesto["report"]["lido_withdrawal_credentials"].as_str().unwrap());

    // Step 3: Compute lido state
    let lido_state = LidoValidatorState::compute_from_beacon_state(&beacon_state, &lido_withdrawal_creds);

    // Step 4: verify state
    verify_state(&beacon_state, &lido_state, &manifesto);

    // Step 5: ensure report merkle root computes
    let merkle_root = lido_state.tree_hash_root();
    log::info!("State merkle root {}", hex::encode(merkle_root));
    log::debug!(
        "Deposited validators: {:?}",
        lido_state.deposited_lido_validator_indices.to_vec()
    );
    log::debug!(
        "Future deposit validators: {:?}",
        lido_state.future_deposit_lido_validator_indices.to_vec()
    );
    log::debug!(
        "Exited validators: {:?}",
        lido_state.exited_lido_validator_indices.to_vec()
    );
}
