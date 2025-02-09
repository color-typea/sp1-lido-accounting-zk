use hex;
use itertools::Itertools;
use rs_merkle;
use std::any::type_name;

use ssz_types::VariableList;
use typenum::Unsigned;

use crate::eth_consensus_layer::Hash256;
use crate::hashing;

use tree_hash::TreeHash;

type MerkleHash = [u8; 32];
type LeafIndex = usize;

#[derive(Debug)]
pub enum Error {
    PreconditionError(String),
    ProofError(rs_merkle::Error),
    DeserializationError(rs_merkle::Error),
    HashesMistmatch(String, Hash256, Hash256),
}

const ZEROHASH: [u8; 32] = [0u8; 32];

pub struct MerkleProofWrapper {
    proof: rs_merkle::MerkleProof<rs_merkle::algorithms::Sha256>,
}

impl MerkleProofWrapper {
    pub fn from_hashes(hashes: Vec<Hash256>, indices: &[LeafIndex]) -> Self {
        // Quirk: rs_merkle does not pad to next power of two, ending up with a different merkle root
        let pad_to = hashes.len().next_power_of_two();
        assert!(
            pad_to >= hashes.len(),
            "Overflow happened finding the padding size: list len: {}, pad_to: {}",
            hashes.len(),
            pad_to
        );
        // Quirks:
        // * rs_merkle produces different values for different sequences of indices - the "correct one" happens when indices are sorted
        // * rs_merkle produces different values if indices are duplicated
        // Solution: make them unique and sorted
        let unique_sorted: Vec<LeafIndex> = indices.iter().unique().sorted().cloned().collect();

        let leaves_vec: Vec<MerkleHash> = hashes
            .iter()
            .map(|val| val.0)
            .pad_using(pad_to, |_i| ZEROHASH)
            .collect();

        let merkle_tree = rs_merkle::MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(leaves_vec.as_slice());
        Self {
            proof: merkle_tree.proof(&unique_sorted),
        }
    }

    pub fn from_instance<T>(instance: &T, field_names: &[T::TFields]) -> Self
    where
        T: MerkleTreeFieldLeaves + TreeHash + StaticFieldProof<T>,
    {
        Self::from_hashes(instance.tree_field_leaves(), &T::get_leafs_indices(field_names))
    }

    fn from_variable_list<T, N>(list: &VariableList<T, N>, indices: &[usize]) -> Self
    where
        T: TreeHash,
        N: Unsigned,
    {
        let hashes = list.iter().map(|val| val.tree_hash_root()).collect();
        Self::from_hashes(hashes, indices)
    }

    pub fn proof_hashes_hex(&self) -> Vec<String> {
        self.proof.proof_hashes_hex()
    }

    pub fn build_root_from_proof(
        &self,
        total_leaves_count: usize,
        indices: &[LeafIndex],
        element_hashes: &[Hash256],
        expand_to_depth: Option<usize>,
        mix_in_size: Option<usize>,
    ) -> Result<Hash256, Error> {
        // Quirk: rs_merkle does not seem pad trees to the next power of two, resulting in hashes that don't match
        // ones computed by ssz
        let leaves_count = total_leaves_count.next_power_of_two();

        if leaves_count < element_hashes.len() {
            return Err(Error::PreconditionError(format!(
                "Total number of elements {} must be >= the number of leafs to prove {}",
                leaves_count,
                element_hashes.len()
            )));
        }
        if indices.len() != element_hashes.len() {
            return Err(Error::PreconditionError(format!(
                "Number of leafs {} != number of indices {}",
                indices.len(),
                element_hashes.len()
            )));
        }
        if !indices.iter().all_unique() {
            return Err(Error::PreconditionError("Indices must be unique".to_owned()));
        }

        let mut leaf_hashes: Vec<MerkleHash> = Vec::with_capacity(element_hashes.len());
        for element_hash in element_hashes {
            leaf_hashes.push(element_hash.0);
        }

        let mut root = self
            .proof
            .root(indices, &leaf_hashes, leaves_count)
            .map_err(Error::ProofError)?
            .into();

        log::debug!("Main data hash {}", hex::encode(root));
        if let Some(target_depth) = expand_to_depth {
            let main_data_depth: usize = leaves_count.trailing_zeros() as usize;
            root = hashing::pad_to_depth(&root, main_data_depth, target_depth);
        }
        if let Some(size) = mix_in_size {
            log::debug!("Mixing in size {} to {}", size, hex::encode(root));
            root = tree_hash::mix_in_length(&root, size);
        }

        Ok(root)
    }
}

pub trait MerkleTreeFieldLeaves {
    const FIELD_COUNT: usize;
    type TFields;

    fn get_tree_leaf_count() -> usize {
        Self::FIELD_COUNT.next_power_of_two()
    }

    fn get_leaf_index(field_name: &Self::TFields) -> LeafIndex;

    fn get_leafs_indices(field_names: &[Self::TFields]) -> Vec<LeafIndex> {
        field_names.iter().map(|v| Self::get_leaf_index(v)).collect()
    }

    fn get_leafs_indices_const<const N: usize>(field_names: &[Self::TFields; N]) -> [LeafIndex; N] {
        let mut result: [LeafIndex; N] = [0; N];
        for (idx, name) in field_names.iter().enumerate() {
            result[idx] = Self::get_leaf_index(name);
        }
        result
    }

    // This requires const generic that blocks/breaks FieldProof blanket implementation
    // fn get_fields(&self) -> [Hash256; FIELD_COUNT];
    // so we do this instead
    fn get_fields(&self) -> Vec<Hash256>;

    fn tree_field_leaves(&self) -> Vec<Hash256> {
        self.get_fields()
    }
}

pub mod serde {
    use super::{Error, MerkleProofWrapper};
    use rs_merkle::{proof_serializers, MerkleProof};

    pub fn deserialize_proof(proof_bytes: &[u8]) -> Result<MerkleProofWrapper, Error> {
        MerkleProof::deserialize::<proof_serializers::DirectHashesOrder>(proof_bytes)
            .map_err(Error::DeserializationError)
            .map(|proof| MerkleProofWrapper { proof })
    }

    pub fn serialize_proof(proof: MerkleProofWrapper) -> Vec<u8> {
        proof.proof.serialize::<proof_serializers::DirectHashesOrder>()
    }
}

pub fn verify_hashes(expected: &Hash256, actual: &Hash256) -> Result<(), Error> {
    if actual == expected {
        return Ok(());
    }

    let err_msg = format!(
        "Root constructed from proof ({}) != actual ({})",
        hex::encode(expected),
        hex::encode(actual)
    );
    Err(Error::HashesMistmatch(err_msg, *actual, *expected))
}

pub trait StaticFieldProof<T: MerkleTreeFieldLeaves> {
    fn verify(
        proof: &MerkleProofWrapper,
        indices: &[T::TFields],
        leaves: &[Hash256],
        expected_hash: &Hash256,
    ) -> Result<(), Error>;
}

impl<T> StaticFieldProof<T> for T
where
    T: MerkleTreeFieldLeaves,
{
    fn verify(
        proof: &MerkleProofWrapper,
        indices: &[T::TFields],
        leaves: &[Hash256],
        expected_hash: &Hash256,
    ) -> Result<(), Error> {
        let field_indices: Vec<usize> = indices.iter().map(|v| T::get_leaf_index(v)).collect();
        let root_from_proof =
            proof.build_root_from_proof(T::get_tree_leaf_count(), &field_indices, leaves, None, None)?;

        verify_hashes(expected_hash, &root_from_proof)
    }
}

pub trait FieldProof {
    type LeafIndex;
    fn get_members_multiproof(&self, indices: &[Self::LeafIndex]) -> MerkleProofWrapper;

    fn get_serialized_multiproof(&self, indices: &[Self::LeafIndex]) -> Vec<u8> {
        serde::serialize_proof(self.get_members_multiproof(indices))
    }

    fn verify_instance(
        &self,
        proof: &MerkleProofWrapper,
        indices: &[Self::LeafIndex],
        element_hashes: &[Hash256],
    ) -> Result<(), Error>;

    fn verify_serialized(
        &self,
        proof_bytes: &Vec<u8>,
        indices: &[Self::LeafIndex],
        element_hashes: &[Hash256],
    ) -> Result<(), Error> {
        let proof = serde::deserialize_proof(proof_bytes.as_slice())?;

        self.verify_instance(&proof, indices, element_hashes)
    }
}

impl<T> FieldProof for T
where
    T: MerkleTreeFieldLeaves + TreeHash + StaticFieldProof<T>,
{
    type LeafIndex = T::TFields;
    fn get_members_multiproof(&self, indices: &[Self::LeafIndex]) -> MerkleProofWrapper {
        MerkleProofWrapper::from_instance(self, indices)
    }

    fn verify_instance(
        &self,
        proof: &MerkleProofWrapper,
        indices: &[Self::LeafIndex],
        element_hashes: &[Hash256],
    ) -> Result<(), Error> {
        Self::verify(proof, indices, element_hashes, &self.tree_hash_root())
    }
}

impl<T, N> FieldProof for VariableList<T, N>
where
    T: TreeHash,
    N: Unsigned,
{
    type LeafIndex = usize;

    fn get_members_multiproof(&self, indices: &[LeafIndex]) -> MerkleProofWrapper {
        assert!(
            hashing::packing_factor::<T>() == 1,
            "Multiproof is not yet supported for type {} that involve packing",
            type_name::<T>()
        );

        MerkleProofWrapper::from_variable_list(self, indices)
    }

    fn verify_instance(
        &self,
        proof: &MerkleProofWrapper,
        indices: &[Self::LeafIndex],
        element_hashes: &[Hash256],
    ) -> Result<(), Error> {
        assert!(
            hashing::packing_factor::<T>() == 1,
            "multiproof is not yet supported for types that involve packing",
        );

        let with_height = proof.build_root_from_proof(
            self.len(),
            indices,
            element_hashes,
            Some(hashing::target_tree_depth::<T, N>()),
            Some(self.len()),
        )?;

        verify_hashes(&self.tree_hash_root(), &with_height)
    }
}

#[cfg(test)]
mod test {
    use alloy_primitives::U256;
    use sp1_lido_accounting_zk_shared_merkle_tree_leaves_derive::MerkleTreeFieldLeaves;
    use ssz_types::VariableList;
    use tree_hash::TreeHash;
    use tree_hash_derive::TreeHash;
    use typenum::Unsigned;

    use crate::{eth_consensus_layer::Hash256, hashing};

    use super::{verify_hashes, FieldProof, LeafIndex, MerkleHash, MerkleTreeFieldLeaves};

    #[derive(Debug, Clone, PartialEq, TreeHash, MerkleTreeFieldLeaves)]
    pub struct GuineaPig {
        pub uint1: u64,
        pub uint2: u64,
        pub hash: Hash256,
    }

    impl GuineaPig {
        fn new(uint1: u64, uint2: u64, hash: Hash256) -> Self {
            GuineaPig { uint1, uint2, hash }
        }
    }

    fn struct_round_trip(guinea_pig: GuineaPig, fields: &[<GuineaPig as MerkleTreeFieldLeaves>::TFields]) {
        let proof = guinea_pig.get_members_multiproof(fields);
        let all_leaves = guinea_pig.tree_field_leaves();
        let target_indices = GuineaPig::get_leafs_indices(fields);
        let target_leaves: Vec<Hash256> = target_indices.iter().map(|idx| all_leaves[*idx]).collect();
        guinea_pig
            .verify_instance(&proof, fields, &target_leaves)
            .expect("Verification failed")
    }

    #[test]
    fn test_struct_round_trip() {
        struct_round_trip(GuineaPig::new(1, 2, Hash256::ZERO), &GuineaPigFields::all());
        struct_round_trip(
            GuineaPig::new(1, 2, Hash256::ZERO),
            &[GuineaPigFields::hash, GuineaPigFields::uint1],
        );
        // Handling duplicates
        // struct_round_trip(
        //     GuineaPig::new(1, 2, Hash256::random()),
        //     &[GuineaPigFields::hash, GuineaPigFields::hash],
        // );
        struct_round_trip(
            GuineaPig::new(10, 20, Hash256::random()),
            &[GuineaPigFields::uint2, GuineaPigFields::uint1],
        );
    }

    fn test_list<N: Unsigned>(input: &[GuineaPig], target_indices: &[usize]) {
        let list: VariableList<GuineaPig, N> = input.to_vec().into();
        let target_hashes: Vec<Hash256> = target_indices
            .iter()
            .map(|index| input[*index].tree_hash_root())
            .collect();

        let proof = list.get_members_multiproof(target_indices);
        list.verify_instance(&proof, target_indices, target_hashes.as_slice())
            .expect("Verification failed")
    }

    #[test]
    fn variable_list_round_trip() {
        let guinea_pigs = vec![
            GuineaPig::new(1, 10, Hash256::ZERO),
            GuineaPig::new(2, 20, Hash256::random()),
            GuineaPig::new(3, 30, Hash256::random()),
            GuineaPig::new(4, 40, Hash256::random()),
            GuineaPig::new(5, 50, Hash256::random()),
        ];

        test_list::<typenum::U4>(&guinea_pigs, &[0, 2]);
        // test_list::<typenum::U4>(&guinea_pigs, &[0, 0, 2]);
        test_list::<typenum::U4>(&guinea_pigs, &[2, 0]);
        test_list::<typenum::U9>(&guinea_pigs, &[0, 1]);
        test_list::<typenum::U31>(&guinea_pigs, &[0, 1, 2]);
        test_list::<typenum::U31>(&guinea_pigs, &[0, 2, 1]);
        test_list::<typenum::U32>(&guinea_pigs, &[2]);
        test_list::<typenum::U255>(&guinea_pigs, &[1]);
        test_list::<typenum::U999>(&guinea_pigs, &[0, 1, 2, 3]);
        test_list::<typenum::U999>(&guinea_pigs, &[3, 2, 1, 0]);
        test_list::<typenum::U999>(&guinea_pigs, &[3, 1, 2, 0]);
    }

    fn test_list_against_hash<N: Unsigned>(input: &[GuineaPig], target_indices: &[usize]) {
        let list: VariableList<GuineaPig, N> = input.to_vec().into();

        let expected_root = list.tree_hash_root();
        let total_leaves_count = input.len().next_power_of_two();
        let target_depth = hashing::target_tree_depth::<GuineaPig, N>();

        let target_hashes: Vec<Hash256> = target_indices
            .iter()
            .map(|index| input[*index].tree_hash_root())
            .collect();

        let proof = list.get_members_multiproof(target_indices);
        let actiual_hash = proof
            .build_root_from_proof(
                total_leaves_count,
                target_indices,
                target_hashes.as_slice(),
                Some(target_depth),
                Some(input.len()),
            )
            .expect("Failed to build hash");

        verify_hashes(&actiual_hash, &expected_root).expect("Verification failed");
    }

    #[test]
    fn variable_list_verify_against_hash() {
        let guinea_pigs = vec![
            GuineaPig::new(1, 10, Hash256::ZERO),
            GuineaPig::new(2, 20, Hash256::random()),
            GuineaPig::new(3, 30, Hash256::random()),
            GuineaPig::new(4, 40, Hash256::random()),
            GuineaPig::new(5, 50, Hash256::random()),
            GuineaPig::new(6, 60, Hash256::random()),
        ];

        test_list_against_hash::<typenum::U8>(&guinea_pigs, &[0, 2]);
        // test_list_against_hash::<typenum::U8>(&guinea_pigs, &[0, 0, 2]);
        test_list_against_hash::<typenum::U8>(&guinea_pigs, &[2, 0]);
        test_list_against_hash::<typenum::U9>(&guinea_pigs, &[0, 1]);
        test_list_against_hash::<typenum::U31>(&guinea_pigs, &[0, 1, 2]);
        test_list_against_hash::<typenum::U31>(&guinea_pigs, &[0, 2, 1]);
        test_list_against_hash::<typenum::U32>(&guinea_pigs, &[2]);
        test_list_against_hash::<typenum::U255>(&guinea_pigs, &[1]);
        test_list_against_hash::<typenum::U999>(&guinea_pigs, &[0, 1, 2, 3]);
        test_list_against_hash::<typenum::U999>(&guinea_pigs, &[3, 2, 1, 0]);
        test_list_against_hash::<typenum::U999>(&guinea_pigs, &[3, 1, 2, 0]);
    }

    fn rs_merkle_compute_ssz_list_hash<Item: TreeHash, N: typenum::Unsigned>(
        list: &VariableList<Item, N>,
        verify_indices: &[usize],
        element_hashes: &[Hash256],
        proof: &super::MerkleProofWrapper,
    ) -> alloy_primitives::FixedBytes<32> {
        let list_len = list.len();
        let target_depth = hashing::target_tree_depth::<Item, N>();
        let leaf_hashes: Vec<MerkleHash> = element_hashes.iter().map(|e| e.0).collect();
        tree_hash::mix_in_length(
            &hashing::pad_to_depth(
                &proof
                    .proof
                    .root(verify_indices, &leaf_hashes, list_len.next_power_of_two())
                    .expect("Should succeed")
                    .into(),
                list_len.trailing_zeros() as usize,
                target_depth,
            ),
            list_len,
        )
    }

    fn wrapped_proof_compute_ssz_list_hash<Item: TreeHash, N: typenum::Unsigned>(
        list: &VariableList<Item, N>,
        verify_indices: &[usize],
        element_hashes: &[Hash256],
        proof: super::MerkleProofWrapper,
    ) -> Result<alloy_primitives::FixedBytes<32>, super::Error> {
        let list_len = list.len();
        let target_depth = hashing::target_tree_depth::<Item, N>();
        proof.build_root_from_proof(
            list_len,
            verify_indices,
            element_hashes,
            Some(target_depth),
            Some(list_len),
        )
    }

    #[test]
    fn test_duplicate_handling() {
        let raw_vec: Vec<U256> = [1u64, 2, 3, 4, 5, 6, 7, 8].iter().map(|v| U256::from(*v)).collect();
        let list: VariableList<U256, typenum::U8> = raw_vec.into();
        let expected_root = list.tree_hash_root();

        let verify_indices: Vec<LeafIndex> = vec![2, 2, 3];
        let proof_indices: Vec<LeafIndex> = vec![2, 3];
        let hashes: Vec<Hash256> = vec![
            U256::from(3).tree_hash_root(),
            U256::from(4).tree_hash_root(),
            U256::from(12).tree_hash_root(), // non-existent leaf
        ];

        let proof = list.get_members_multiproof(&proof_indices);

        let raw_proof_root = rs_merkle_compute_ssz_list_hash(&list, &verify_indices, &hashes, &proof);
        // Exposes rs_merkle allowing duplicates with
        // See https://github.com/color-typea/sp1-lido-accounting-zk/issues/5
        let raw_proof_result = verify_hashes(&raw_proof_root, &expected_root);
        assert!(raw_proof_result.is_ok());

        let wrapped_proof_root = wrapped_proof_compute_ssz_list_hash(&list, &verify_indices, &hashes, proof);

        // Demonstrates wrapper fixes the problem
        assert!(wrapped_proof_root.is_err())
    }
}
