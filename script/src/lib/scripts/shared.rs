use crate::validator_delta::ValidatorDeltaCompute;
use alloy_sol_types::SolType;

use sp1_sdk::SP1PublicValues;

use sp1_lido_accounting_zk_shared::circuit_logic::input_verification::{InputVerifier, LogCycleTracker};
use sp1_lido_accounting_zk_shared::circuit_logic::report::ReportData;
use sp1_lido_accounting_zk_shared::eth_consensus_layer::{
    BeaconBlockHeader, BeaconState, BeaconStateFields, ExecutionPayloadHeader, ExecutionPayloadHeaderFields, Hash256,
};
use sp1_lido_accounting_zk_shared::io::eth_io::{
    BeaconChainSlot, HaveEpoch, HaveSlotWithBlock, LidoValidatorStateRust, PublicValuesRust, PublicValuesSolidity,
    ReferenceSlot, ReportMetadataRust, ReportRust,
};
use sp1_lido_accounting_zk_shared::io::program_io::{
    ExecutionPayloadHeaderData, ProgramInput, ValsAndBals, WithdrawalVaultData,
};
use sp1_lido_accounting_zk_shared::lido::LidoValidatorState;
use sp1_lido_accounting_zk_shared::merkle_proof::{FieldProof, MerkleTreeFieldLeaves};
use sp1_lido_accounting_zk_shared::util::{u64_to_usize, usize_to_u64};

use anyhow::Result;

use tree_hash::TreeHash;

pub fn prepare_program_input(
    reference_slot: ReferenceSlot,
    bs: &BeaconState,
    bh: &BeaconBlockHeader,
    old_bs: &BeaconState,
    lido_withdrawal_credentials: &Hash256,
    lido_withdrawal_vault_data: WithdrawalVaultData,
    verify: bool,
) -> (ProgramInput, PublicValuesRust) {
    let beacon_block_hash = bh.tree_hash_root();

    log::info!(
        "Processing BeaconState. Current slot: {}, Previous Slot: {}, Block Hash: {}, Validator count:{}",
        bs.slot,
        old_bs.slot,
        hex::encode(beacon_block_hash),
        bs.validators.len()
    );
    let old_validator_state = LidoValidatorState::compute_from_beacon_state(old_bs, lido_withdrawal_credentials);
    let new_validator_state = LidoValidatorState::compute_from_beacon_state(bs, lido_withdrawal_credentials);

    log::info!(
        "Computed validator states. Old: deposited {}, pending {}, exited {}. New: deposited {}, pending {}, exited {}",
        old_validator_state.deposited_lido_validator_indices.len(),
        old_validator_state.pending_deposit_lido_validator_indices.len(),
        old_validator_state.exited_lido_validator_indices.len(),
        new_validator_state.deposited_lido_validator_indices.len(),
        new_validator_state.pending_deposit_lido_validator_indices.len(),
        new_validator_state.exited_lido_validator_indices.len(),
    );

    let report = ReportData::compute(
        reference_slot,
        bs.epoch(),
        &bs.validators,
        &bs.balances,
        lido_withdrawal_credentials,
    );

    let public_values: PublicValuesRust = PublicValuesRust {
        report: ReportRust {
            reference_slot: report.slot,
            deposited_lido_validators: report.deposited_lido_validators,
            exited_lido_validators: report.exited_lido_validators,
            lido_cl_balance: report.lido_cl_balance,
            lido_withdrawal_vault_balance: lido_withdrawal_vault_data.balance,
        },
        metadata: ReportMetadataRust {
            bc_slot: bs.bc_slot(),
            epoch: report.epoch,
            lido_withdrawal_credentials: lido_withdrawal_credentials.to_fixed_bytes(),
            beacon_block_hash: beacon_block_hash.to_fixed_bytes(),
            state_for_previous_report: LidoValidatorStateRust {
                slot: old_validator_state.bc_slot(),
                merkle_root: old_validator_state.tree_hash_root().to_fixed_bytes(),
            },
            new_state: LidoValidatorStateRust {
                slot: new_validator_state.slot,
                merkle_root: new_validator_state.tree_hash_root().to_fixed_bytes(),
            },
            withdrawal_vault_data: lido_withdrawal_vault_data.clone().into(),
        },
    };

    log::info!("Computed report and public values");
    log::debug!("Report {report:?}");
    log::debug!("Public values {public_values:?}");

    let validator_delta = ValidatorDeltaCompute::new(old_bs, &old_validator_state, bs, !verify).compute();
    log::info!(
        "Computed validator delta. Added: {}, lido changed: {}",
        validator_delta.all_added.len(),
        validator_delta.lido_changed.len(),
    );
    let added_indices: Vec<usize> = validator_delta.added_indices().map(|v| u64_to_usize(*v)).collect();
    let changed_indices: Vec<usize> = validator_delta
        .lido_changed_indices()
        .map(|v| u64_to_usize(*v))
        .collect();

    let added_validators_proof = bs.validators.get_serialized_multiproof(added_indices.as_slice());
    let changed_validators_proof = bs.validators.get_serialized_multiproof(changed_indices.as_slice());
    log::info!("Obtained added and changed validators multiproofs");

    let bs_indices = BeaconState::get_leafs_indices([BeaconStateFields::validators, BeaconStateFields::balances]);
    let validators_and_balances_proof = bs.get_serialized_multiproof(bs_indices.as_slice());
    log::info!("Obtained validators and balances fields multiproof");

    let execution_header_indices =
        ExecutionPayloadHeader::get_leafs_indices([ExecutionPayloadHeaderFields::state_root]);
    let eh_state_root_proof = bs
        .latest_execution_payload_header
        .get_serialized_multiproof(execution_header_indices.as_slice());
    log::info!("Obtained BeaconState.latest_execution_header.state_root proof");

    log::info!("Creating program input");
    let program_input = ProgramInput {
        reference_slot,
        bc_slot: bs.bc_slot(),
        beacon_block_hash,
        beacon_block_header: bh.into(),
        latest_execution_header_data: ExecutionPayloadHeaderData {
            state_root: bs.latest_execution_payload_header.state_root,
            state_root_inclusion_proof: eh_state_root_proof,
        },
        beacon_state: bs.into(),
        validators_and_balances: ValsAndBals {
            validators_and_balances_proof,
            lido_withdrawal_credentials: *lido_withdrawal_credentials,
            total_validators: usize_to_u64(bs.validators.len()),
            validators_delta: validator_delta,
            added_validators_inclusion_proof: added_validators_proof,
            changed_validators_inclusion_proof: changed_validators_proof,
            balances: bs.balances.clone(),
        },
        old_lido_validator_state: old_validator_state.clone(),
        new_lido_validator_state_hash: new_validator_state.tree_hash_root(),

        withdrawal_vault_data: lido_withdrawal_vault_data,
    };

    if verify {
        verify_input_correctness(
            bs.bc_slot(),
            &program_input,
            &old_validator_state,
            &new_validator_state,
            lido_withdrawal_credentials,
        )
        .expect("Failed to verify input correctness");
    }

    (program_input, public_values)
}

fn verify_input_correctness(
    slot: BeaconChainSlot,
    program_input: &ProgramInput,
    old_state: &LidoValidatorState,
    new_state: &LidoValidatorState,
    lido_withdrawal_credentials: &Hash256,
) -> Result<()> {
    log::debug!("Verifying inputs");
    let cycle_tracker = LogCycleTracker {};
    let input_verifier = InputVerifier::new(&cycle_tracker);
    input_verifier.prove_input(program_input);
    log::debug!("Inputs verified");

    log::debug!("Verifying old_state + validator_delta = new_state");
    let delta = &program_input.validators_and_balances.validators_delta;
    let computed_new_state = old_state.merge_validator_delta(slot, delta, lido_withdrawal_credentials);
    assert_eq!(computed_new_state, *new_state);
    assert_eq!(
        computed_new_state.tree_hash_root(),
        program_input.new_lido_validator_state_hash
    );
    log::debug!("New state verified");
    Ok(())
}

pub fn verify_public_values(public_values: &SP1PublicValues, expected_public_values: &PublicValuesRust) -> Result<()> {
    let public_values_solidity: PublicValuesSolidity =
        PublicValuesSolidity::abi_decode(public_values.as_slice(), true)?;
    let public_values_rust: PublicValuesRust = public_values_solidity.into();

    log::debug!(
        "Expected hash: {}",
        hex::encode(expected_public_values.metadata.beacon_block_hash)
    );
    log::debug!(
        "Computed hash: {}",
        hex::encode(public_values_rust.metadata.beacon_block_hash)
    );
    assert!(public_values_rust == *expected_public_values);
    log::info!("Public values match!");

    Ok(())
}
