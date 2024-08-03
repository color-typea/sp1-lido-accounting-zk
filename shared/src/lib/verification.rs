use rs_merkle::{algorithms::Sha256, MerkleProof, MerkleTree};

use hex;
use hex_literal::hex as h;

use crate::eth_consensus_layer::{BeaconState, Hash256};

use tree_hash::TreeHash;

type LeafIndex = usize;
type RsMerkleHash = <Sha256 as rs_merkle::Hasher>::Hash;

// TODO: better error
#[derive(Debug)]
pub enum Error {
    FieldDoesNotExist(String),
    VerificationError(),
}

const ZEROHASH: [u8; 32] = h!("0000000000000000000000000000000000000000000000000000000000000000");

pub trait MerkleTreeFieldLeaves {
    fn get_leaf_index(&self, field_name: &str) -> Result<LeafIndex, Error>;
    fn get_leafs_indices<const N: usize>(&self, field_names: [&str; N]) -> Result<[LeafIndex; N], Error> {
        let mut result: [LeafIndex; N] = [0; N];
        for (idx, name) in field_names.iter().enumerate() {
            result[idx] = self.get_leaf_index(name)?;
        }
        return Ok(result);
    }
    fn tree_field_leaves(&self) -> Vec<Hash256>;
}

fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

pub trait FieldProof {
    fn get_field_multiproof(&self, indices: &[LeafIndex]) -> MerkleProof<Sha256>;
    fn verify(&self, proof: &MerkleProof<Sha256>, indices: &[LeafIndex]) -> Result<(), Error>;
}

impl<T> FieldProof for T
where
    T: MerkleTreeFieldLeaves + TreeHash,
{
    fn get_field_multiproof(&self, indices: &[LeafIndex]) -> MerkleProof<Sha256> {
        let leaves_as_h256 = self.tree_field_leaves();
        let leaves_vec: Vec<RsMerkleHash> = leaves_as_h256
            .iter()
            .map(|val| val.as_fixed_bytes().to_owned())
            .collect();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(leaves_vec.as_slice());

        return merkle_tree.proof(indices);
    }

    fn verify(&self, proof: &MerkleProof<Sha256>, indices: &[LeafIndex]) -> Result<(), Error> {
        let leaves_as_h256 = self.tree_field_leaves();
        let total_leaves_count = leaves_as_h256.len();
        // Quirk: rs_merkle does not pad to next power of two
        assert!(is_power_of_two(total_leaves_count));

        let leaves_vec: Vec<&RsMerkleHash> = leaves_as_h256.iter().map(|val| val.as_fixed_bytes()).collect();

        let leaves_to_prove: Vec<RsMerkleHash> = indices.iter().map(|idx| leaves_vec[*idx].to_owned()).collect();

        let verifies: bool = proof.verify(
            self.tree_hash_root().as_fixed_bytes().to_owned(),
            indices,
            leaves_to_prove.as_slice(),
            total_leaves_count,
        );
        if verifies {
            return Ok(());
        } else {
            return Err(Error::VerificationError());
        }
    }
}

// TODO: derive
impl MerkleTreeFieldLeaves for BeaconState {
    fn get_leaf_index(&self, field_name: &str) -> Result<LeafIndex, Error> {
        let start_index = 0;
        match field_name {
            "genesis_time" => Ok(start_index + 0),
            "genesis_validators_root" => Ok(start_index + 1),
            "slot" => Ok(start_index + 2),
            "fork" => Ok(start_index + 3),
            "latest_block_header" => Ok(start_index + 4),
            "block_roots" => Ok(start_index + 5),
            "state_roots" => Ok(start_index + 6),
            "historical_roots" => Ok(start_index + 7),
            "eth1_data" => Ok(start_index + 8),
            "eth1_data_votes" => Ok(start_index + 9),
            "eth1_deposit_index" => Ok(start_index + 10),
            "validators" => Ok(start_index + 11),
            "balances" => Ok(start_index + 12),
            "randao_mixes" => Ok(start_index + 13),
            "slashings" => Ok(start_index + 14),
            "previous_epoch_participation" => Ok(start_index + 15),
            "current_epoch_participation" => Ok(start_index + 16),
            "justification_bits" => Ok(start_index + 17),
            "previous_justified_checkpoint" => Ok(start_index + 18),
            "current_justified_checkpoint" => Ok(start_index + 19),
            "finalized_checkpoint" => Ok(start_index + 20),
            "inactivity_scores" => Ok(start_index + 21),
            "current_sync_committee" => Ok(start_index + 22),
            "next_sync_committee" => Ok(start_index + 23),
            "latest_execution_payload_header" => Ok(start_index + 24),
            "next_withdrawal_index" => Ok(start_index + 25),
            "next_withdrawal_validator_index" => Ok(start_index + 26),
            "historical_summaries" => Ok(start_index + 27),
            _ => Err(Error::FieldDoesNotExist(format!("Field {} does not exist", field_name))),
        }
    }

    fn tree_field_leaves(&self) -> Vec<Hash256> {
        return vec![
            self.genesis_time.tree_hash_root(),
            self.genesis_validators_root.tree_hash_root(),
            self.slot.tree_hash_root(),
            self.fork.tree_hash_root(),
            self.latest_block_header.tree_hash_root(),
            self.block_roots.tree_hash_root(),
            self.state_roots.tree_hash_root(),
            self.historical_roots.tree_hash_root(),
            self.eth1_data.tree_hash_root(),
            self.eth1_data_votes.tree_hash_root(),
            self.eth1_deposit_index.tree_hash_root(),
            self.validators.tree_hash_root(),
            self.balances.tree_hash_root(),
            self.randao_mixes.tree_hash_root(),
            self.slashings.tree_hash_root(),
            self.previous_epoch_participation.tree_hash_root(),
            self.current_epoch_participation.tree_hash_root(),
            self.justification_bits.tree_hash_root(),
            self.previous_justified_checkpoint.tree_hash_root(),
            self.current_justified_checkpoint.tree_hash_root(),
            self.finalized_checkpoint.tree_hash_root(),
            self.inactivity_scores.tree_hash_root(),
            self.current_sync_committee.tree_hash_root(),
            self.next_sync_committee.tree_hash_root(),
            self.latest_execution_payload_header.tree_hash_root(),
            self.next_withdrawal_index.tree_hash_root(),
            self.next_withdrawal_validator_index.tree_hash_root(),
            self.historical_summaries.tree_hash_root(),
            // padding to the nearest power of 2 - rs_merkle doesn't seem to do it
            ZEROHASH.into(),
            ZEROHASH.into(),
            ZEROHASH.into(),
            ZEROHASH.into(),
        ];
    }
}
