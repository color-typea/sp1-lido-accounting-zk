use serde::{Deserialize, Serialize};

use crate::{
    eth_consensus_layer::{Balances, BeaconBlockHeaderPrecomputedHashes, BeaconStatePrecomputedHashes, Hash256},
    lido::{LidoValidatorState, ValidatorDelta},
};

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct ProgramInput {
    pub slot: u64,
    pub beacon_block_hash: Hash256,
    pub beacon_block_header: BeaconBlockHeaderPrecomputedHashes,
    pub beacon_state: BeaconStatePrecomputedHashes,
    pub validators_and_balances: ValsAndBals,
    pub old_lido_validator_state: LidoValidatorState,
    pub new_lido_validator_state_hash: Hash256,
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct ValsAndBals {
    pub validators_and_balances_proof: Vec<u8>,

    pub validators_delta: ValidatorDelta,
    pub added_validators_inclusion_proof: Vec<u8>,
    pub changed_validators_inclusion_proof: Vec<u8>,

    pub balances: Balances, // all balances
}
