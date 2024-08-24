use std::any::type_name;

use rs_merkle::{algorithms::Sha256, proof_serializers, MerkleProof, MerkleTree};

use hex_literal::hex as h;
use serde_json::value::Index;
use ssz_types::VariableList;
use typenum::Unsigned;

use crate::{
    eth_consensus_layer::{BeaconBlockHeader, BeaconState, BeaconStatePrecomputedHashes, Hash256},
    hashing,
};

use itertools::Itertools;
use tree_hash::TreeHash;

type LeafIndex = usize;
pub type RsMerkleHash = <Sha256 as rs_merkle::Hasher>::Hash;

// TODO: better error
#[derive(Debug)]
pub enum Error {
    FieldDoesNotExist(String),
    ProofError(rs_merkle::Error),
    DeserializationError(rs_merkle::Error),
    HashesMistmatch(String, Hash256, Hash256),
}

const ZEROHASH: [u8; 32] = h!("0000000000000000000000000000000000000000000000000000000000000000");
const ZEROHASH_H256: Hash256 = Hash256::zero();

pub trait MerkleTreeFieldLeaves {
    const TREE_FIELDS_LENGTH: usize;
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

fn verify_hashes(expected: &Hash256, actual: &Hash256) -> Result<(), Error> {
    if actual == expected {
        return Ok(());
    }

    let err_msg = format!(
        "Root constructed from proof ({}) != actual ({})",
        hex::encode(expected),
        hex::encode(actual)
    );
    return Err(Error::HashesMistmatch(err_msg, actual.clone(), expected.clone()));
}

pub trait FieldProof {
    fn get_field_multiproof(&self, indices: &[LeafIndex]) -> MerkleProof<Sha256>;
    fn verify(&self, proof: &MerkleProof<Sha256>, indices: &[LeafIndex], leafs: &[RsMerkleHash]) -> Result<(), Error>;

    fn get_serialized_multiproof(&self, indices: &[LeafIndex]) -> Vec<u8> {
        let proof = self.get_field_multiproof(indices);
        proof.serialize::<proof_serializers::DirectHashesOrder>()
    }

    fn verify_serialized(
        &self,
        proof_bytes: &Vec<u8>,
        indices: &[LeafIndex],
        leafs: &[RsMerkleHash],
    ) -> Result<(), Error> {
        let maybe_proof = MerkleProof::deserialize::<proof_serializers::DirectHashesOrder>(proof_bytes.as_slice());

        match maybe_proof {
            Ok(proof) => self.verify(&proof, indices, leafs),
            Err(error) => Err(Error::DeserializationError(error)),
        }
    }
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

    fn verify(&self, proof: &MerkleProof<Sha256>, indices: &[LeafIndex], leaves: &[RsMerkleHash]) -> Result<(), Error> {
        // Quirk: rs_merkle does not seem pad trees to the next power of two, resulting in hashes that don't match
        // ones computed by ssz
        assert!(
            T::TREE_FIELDS_LENGTH.is_power_of_two(),
            "{}::TREE_FIELDS_LENGTH should be a power of two, got {}",
            type_name::<T>(),
            T::TREE_FIELDS_LENGTH
        );
        let root_from_proof = build_root_from_proof(proof, T::TREE_FIELDS_LENGTH, indices, leaves, None, None)?;

        return verify_hashes(&self.tree_hash_root(), &root_from_proof);
    }
}

// TODO: derive
impl MerkleTreeFieldLeaves for BeaconState {
    const TREE_FIELDS_LENGTH: usize = 32;
    fn get_leaf_index(&self, field_name: &str) -> Result<LeafIndex, Error> {
        let precomp: BeaconStatePrecomputedHashes = self.into();
        precomp.get_leaf_index(field_name)
    }

    fn tree_field_leaves(&self) -> Vec<Hash256> {
        let precomp: BeaconStatePrecomputedHashes = self.into();
        let fields = precomp.tree_field_leaves();
        // This is just a self-check - if BeaconState grows beyond 32 fields, it should become 64
        assert!(fields.len() == Self::TREE_FIELDS_LENGTH);
        fields
    }
}

// TODO: derive
impl MerkleTreeFieldLeaves for BeaconStatePrecomputedHashes {
    const TREE_FIELDS_LENGTH: usize = 32;
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
        let result = vec![
            self.genesis_time,
            self.genesis_validators_root,
            self.slot,
            self.fork,
            self.latest_block_header,
            self.block_roots,
            self.state_roots,
            self.historical_roots,
            self.eth1_data,
            self.eth1_data_votes,
            self.eth1_deposit_index,
            self.validators,
            self.balances,
            self.randao_mixes,
            self.slashings,
            self.previous_epoch_participation,
            self.current_epoch_participation,
            self.justification_bits,
            self.previous_justified_checkpoint,
            self.current_justified_checkpoint,
            self.finalized_checkpoint,
            self.inactivity_scores,
            self.current_sync_committee,
            self.next_sync_committee,
            self.latest_execution_payload_header,
            self.next_withdrawal_index,
            self.next_withdrawal_validator_index,
            self.historical_summaries,
            // Quirk: padding to the nearest power of 2 - rs_merkle doesn't seem to do it
            ZEROHASH_H256,
            ZEROHASH_H256,
            ZEROHASH_H256,
            ZEROHASH_H256,
        ];
        // This is just a self-check - if BeaconState grows beyond 32 fields, it should become 64
        assert!(result.len() == Self::TREE_FIELDS_LENGTH);
        result
    }
}

// TODO: derive
impl MerkleTreeFieldLeaves for BeaconBlockHeader {
    const TREE_FIELDS_LENGTH: usize = 8;
    fn get_leaf_index(&self, field_name: &str) -> Result<LeafIndex, Error> {
        let start_index = 0;
        match field_name {
            "slot" => Ok(start_index + 0),
            "proposer_index" => Ok(start_index + 1),
            "parent_root" => Ok(start_index + 2),
            "state_root" => Ok(start_index + 3),
            "body_root" => Ok(start_index + 4),
            _ => Err(Error::FieldDoesNotExist(format!("Field {} does not exist", field_name))),
        }
    }

    fn tree_field_leaves(&self) -> Vec<Hash256> {
        let result: Vec<Hash256> = vec![
            self.slot.tree_hash_root(),
            self.proposer_index.tree_hash_root(),
            self.parent_root,
            self.state_root,
            self.body_root,
            // Quirk: padding to the nearest power of 2 - rs_merkle doesn't seem to do it
            ZEROHASH_H256,
            ZEROHASH_H256,
            ZEROHASH_H256,
        ];
        // This is just a self-check - if BeaconState grows beyond 32 fields, it should become 64
        assert!(result.len() == Self::TREE_FIELDS_LENGTH);
        result
    }
}

fn build_root_from_proof(
    proof: &MerkleProof<Sha256>,
    total_leaves_count: usize,
    indices: &[LeafIndex],
    leaves_to_prove: &[RsMerkleHash],
    expand_to_depth: Option<usize>,
    mix_in_size: Option<usize>,
) -> Result<Hash256, Error> {
    assert!(
        total_leaves_count >= leaves_to_prove.len(),
        "Total number of elements {} must be >= the number of leafs to prove {}",
        total_leaves_count,
        leaves_to_prove.len()
    );
    assert!(
        indices.len() == leaves_to_prove.len(),
        "Number of leafs {} != number of indices {}",
        indices.len(),
        leaves_to_prove.len()
    );

    let mut root = proof
        .root(indices, leaves_to_prove, total_leaves_count)
        .map_err(Error::ProofError)?
        .into();

    log::debug!("Main data hash {}", hex::encode(root));
    if let Some(target_depth) = expand_to_depth {
        let main_data_depth: usize = total_leaves_count.trailing_zeros() as usize;
        log::debug!("Expanding depth {} to {}", main_data_depth, target_depth);
        root = hashing::pad_to_depth(&root, main_data_depth, target_depth);
    }
    if let Some(size) = mix_in_size {
        log::debug!("Mixing in size {}", size);
        root = tree_hash::mix_in_length(&root, size);
    }

    return Ok(root);
}

impl<T, N> FieldProof for VariableList<T, N>
where
    T: TreeHash,
    N: Unsigned,
{
    fn get_field_multiproof(&self, indices: &[LeafIndex]) -> MerkleProof<Sha256> {
        assert!(
            hashing::packing_factor::<T>() == 1,
            "Multiproof is not yet supported for type {} that involve packing",
            type_name::<T>()
        );

        // Quirk: rs_merkle does not pad to next power of two, ending up with a different merkle root
        let pad_to = self.len().next_power_of_two();
        assert!(pad_to > self.len(), "Overflow finding the padding size");
        let leaves: Vec<RsMerkleHash> = self
            .iter()
            .map(|val| val.tree_hash_root().to_fixed_bytes())
            .pad_using(pad_to, |_i| ZEROHASH)
            .collect();
        assert!(is_power_of_two(leaves.len()), "Number of leaves must be a power of 2");

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(leaves.as_slice());
        return merkle_tree.proof(indices);
    }

    fn verify(&self, proof: &MerkleProof<Sha256>, indices: &[LeafIndex], leaves: &[RsMerkleHash]) -> Result<(), Error> {
        assert!(
            hashing::packing_factor::<T>() == 1,
            "multiproof is not yet supported for types that involve packing",
        );

        // Quirk: rs_merkle does not pad to next power of two, ending up with a different merkle root
        let total_leaves_count = self.len().next_power_of_two();
        let target_depth = hashing::target_tree_depth::<T, N>();

        let with_height = build_root_from_proof(
            proof,
            total_leaves_count,
            indices,
            leaves,
            Some(target_depth),
            Some(self.len()),
        )?;

        verify_hashes(&self.tree_hash_root(), &with_height)
    }
}
