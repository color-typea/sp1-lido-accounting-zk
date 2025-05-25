use anyhow::anyhow;
use hex_literal::hex;
use sp1_lido_accounting_scripts::consts::{Network, WrappedNetwork};
use sp1_lido_accounting_zk_shared::eth_consensus_layer::{
    BeaconStateFields, BeaconStatePrecomputedHashes, Epoch, Hash256, Validator,
};
use sp1_lido_accounting_zk_shared::io::eth_io::{BeaconChainSlot, ReferenceSlot};

pub mod env;
pub mod files;

pub static NETWORK: WrappedNetwork = WrappedNetwork::Anvil(Network::Sepolia);
pub const DEPLOY_SLOT: BeaconChainSlot = BeaconChainSlot(7643456);

pub const REPORT_COMPUTE_SLOT: BeaconChainSlot = BeaconChainSlot(7700384);

pub fn eyre_to_anyhow(err: eyre::Error) -> anyhow::Error {
    anyhow!("Eyre error: {:#?}", err)
}

// This function not OK to use it outside tests. Don't copy-paste.
// In short:
// * Only a few slots will be reference slots (one a day)
// * Not all reference slots will actually have block in them
#[cfg(test)]
pub fn mark_as_refslot(slot: BeaconChainSlot) -> ReferenceSlot {
    ReferenceSlot(slot.0)
}

pub mod adjustments {
    use sp1_lido_accounting_zk_shared::{
        eth_consensus_layer::{BeaconBlockHeader, BeaconState, Validator},
        io::eth_io::BeaconChainSlot,
    };
    use tree_hash::TreeHash;

    pub struct Adjuster {
        beacon_state: BeaconState,
        block_header: BeaconBlockHeader,
    }

    impl Adjuster {
        pub fn start_with(beacon_state: &BeaconState, block_header: &BeaconBlockHeader) -> Self {
            Self {
                beacon_state: beacon_state.clone(),
                block_header: block_header.clone(),
            }
        }

        pub fn set_slot(mut self, slot: &BeaconChainSlot) -> Self {
            self.beacon_state.slot = slot.0;
            self.block_header.slot = slot.0;
            self
        }

        pub fn add_validator(mut self, validator: Validator, balance: u64) -> Self {
            self.beacon_state
                .validators
                .push(validator)
                .expect("Too many validators");
            self.beacon_state.balances.push(balance).expect("Too many balances");
            self
        }

        pub fn add_validators(mut self, validators: &[Validator], balances: &[u64]) -> Self {
            assert_eq!(
                validators.len(),
                balances.len(),
                "Validators and balances length mismatch"
            );
            for (validator, balance) in validators.iter().zip(balances.iter()) {
                self = self.add_validator(validator.clone(), *balance);
            }
            self
        }

        pub fn set_validator(mut self, index: usize, validator: Validator) -> Self {
            self.beacon_state.validators[index] = validator;
            self
        }

        pub fn set_balance(mut self, index: usize, balance: u64) -> Self {
            self.beacon_state.balances[index] = balance;
            self
        }

        pub fn build(mut self) -> (BeaconState, BeaconBlockHeader) {
            self.block_header.state_root = self.beacon_state.tree_hash_root();
            (self.beacon_state, self.block_header)
        }
    }
}

pub mod validator {
    use rand::Rng;
    use sp1_lido_accounting_zk_shared::{
        eth_consensus_layer::*,
        io::eth_io::{BeaconChainSlot, HaveEpoch},
    };

    pub enum Status {
        Pending(u64),
        Active(u64),
        Exited { activated: u64, exited: u64 },
    }

    impl Status {
        pub fn pending(slot: BeaconChainSlot) -> Self {
            Self::Pending(slot.epoch())
        }
        pub fn active(activation_slot: BeaconChainSlot) -> Self {
            Self::Active(activation_slot.epoch())
        }
        pub fn exited(activation_slot: BeaconChainSlot, exit_slot: BeaconChainSlot) -> Self {
            Self::Exited {
                activated: activation_slot.epoch(),
                exited: exit_slot.epoch(),
            }
        }
    }

    pub fn random_pubkey(prefix: Option<&[u8]>) -> BlsPublicKey {
        let mut pubkey = [0u8; 48];
        let mut rng = rand::rng();

        // Fill with random bytes
        rng.fill(&mut pubkey);

        // Overwrite with prefix if provided
        if let Some(p) = prefix {
            let len = p.len().min(48);
            pubkey[..len].copy_from_slice(&p[..len]);
        }
        pubkey.to_vec().into()
    }

    pub fn make(pubkey: BlsPublicKey, withdrawal_credentials: WithdrawalCredentials, status: Status) -> Validator {
        let (activation_eligibility_epoch, activation_epoch, exit_epoch) = match status {
            Status::Pending(epoch) => (epoch, u64::MAX, u64::MAX),
            Status::Active(deposited) => (deposited - 1, deposited, u64::MAX),
            Status::Exited { activated, exited } => (activated - 1, activated, exited),
        };

        Validator {
            pubkey,
            withdrawal_credentials,
            effective_balance: 32 * 1_000_000_000,
            slashed: false,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch: activation_epoch,
        }
    }
}

pub fn make_validator(current_epoch: Epoch, balance: u64) -> Validator {
    let activation_eligibility_epoch: u64 = current_epoch - 10;
    let activation_epoch: u64 = current_epoch - 5;
    let exit_epoch: u64 = u64::MAX;
    let withdrawable_epoch: u64 = current_epoch - 3;
    let bls_key: Vec<u8> =
        hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").into();

    Validator {
        pubkey: bls_key.into(),
        withdrawal_credentials: hex!("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").into(),
        effective_balance: balance,
        slashed: false,
        activation_eligibility_epoch,
        activation_epoch,
        exit_epoch,
        withdrawable_epoch,
    }
}

pub fn set_bs_field(bs: &mut BeaconStatePrecomputedHashes, field: &BeaconStateFields, value: Hash256) {
    match field {
        BeaconStateFields::genesis_time => bs.genesis_time = value,
        BeaconStateFields::genesis_validators_root => bs.genesis_validators_root = value,
        BeaconStateFields::slot => bs.slot = value,
        BeaconStateFields::fork => bs.fork = value,
        BeaconStateFields::latest_block_header => bs.latest_block_header = value,
        BeaconStateFields::block_roots => bs.block_roots = value,
        BeaconStateFields::state_roots => bs.state_roots = value,
        BeaconStateFields::historical_roots => bs.historical_roots = value,
        BeaconStateFields::eth1_data => bs.eth1_data = value,
        BeaconStateFields::eth1_data_votes => bs.eth1_data_votes = value,
        BeaconStateFields::eth1_deposit_index => bs.eth1_deposit_index = value,
        BeaconStateFields::validators => bs.validators = value,
        BeaconStateFields::balances => bs.balances = value,
        BeaconStateFields::randao_mixes => bs.randao_mixes = value,
        BeaconStateFields::slashings => bs.slashings = value,
        BeaconStateFields::previous_epoch_participation => bs.previous_epoch_participation = value,
        BeaconStateFields::current_epoch_participation => bs.current_epoch_participation = value,
        BeaconStateFields::justification_bits => bs.justification_bits = value,
        BeaconStateFields::previous_justified_checkpoint => bs.previous_justified_checkpoint = value,
        BeaconStateFields::current_justified_checkpoint => bs.current_justified_checkpoint = value,
        BeaconStateFields::finalized_checkpoint => bs.finalized_checkpoint = value,
        BeaconStateFields::inactivity_scores => bs.inactivity_scores = value,
        BeaconStateFields::current_sync_committee => bs.current_sync_committee = value,
        BeaconStateFields::next_sync_committee => bs.next_sync_committee = value,
        BeaconStateFields::latest_execution_payload_header => bs.latest_execution_payload_header = value,
        BeaconStateFields::next_withdrawal_index => bs.next_withdrawal_index = value,
        BeaconStateFields::next_withdrawal_validator_index => bs.next_withdrawal_validator_index = value,
        BeaconStateFields::historical_summaries => bs.historical_summaries = value,
        BeaconStateFields::deposit_requests_start_index => bs.deposit_requests_start_index = value,
        BeaconStateFields::deposit_balance_to_consume => bs.deposit_balance_to_consume = value,
        BeaconStateFields::exit_balance_to_consume => bs.exit_balance_to_consume = value,
        BeaconStateFields::earliest_exit_epoch => bs.earliest_exit_epoch = value,
        BeaconStateFields::consolidation_balance_to_consume => bs.consolidation_balance_to_consume = value,
        BeaconStateFields::earliest_consolidation_epoch => bs.earliest_consolidation_epoch = value,
        BeaconStateFields::pending_deposits => bs.pending_deposits = value,
        BeaconStateFields::pending_partial_withdrawals => bs.pending_partial_withdrawals = value,
        BeaconStateFields::pending_consolidations => bs.pending_consolidations = value,
    }
}

pub mod vecs {
    use rand::{seq::SliceRandom, Rng};

    fn vectors_equal<N: PartialEq>(left: &[N], right: &[N]) -> bool {
        if left.len() != right.len() {
            return false;
        }
        left.iter().zip(right.iter()).all(|(l, r)| l == r)
    }

    pub fn append<Elem>(mut input: Vec<Elem>, element: Elem) -> Vec<Elem> {
        input.push(element);
        input
    }

    pub fn duplicate<Elem: Clone>(mut input: Vec<Elem>, index: usize) -> Vec<Elem> {
        let elem = input[index].clone();
        append(input, elem)
    }

    pub fn duplicate_random<Elem: Clone>(mut input: Vec<Elem>) -> Vec<Elem> {
        let duplicate_idx = rand::rng().random_range(0..input.len());
        duplicate(input, duplicate_idx)
    }

    pub fn modify<Elem: Clone>(mut input: Vec<Elem>, index: usize, modifier: impl Fn(Elem) -> Elem) -> Vec<Elem> {
        let new_val = modifier(input[index].clone());
        input[index] = new_val;
        input
    }

    pub fn modify_random<Elem: Clone>(mut input: Vec<Elem>, modifier: impl Fn(Elem) -> Elem) -> Vec<Elem> {
        let modify_idx = rand::rng().random_range(0..input.len());
        modify(input, modify_idx, modifier)
    }

    pub fn remove<Elem>(mut input: Vec<Elem>, index: usize) -> Vec<Elem> {
        assert!(!input.is_empty(), "Removing from empty vec leaves the input intact");
        input.remove(index);
        input
    }

    pub fn remove_random<Elem>(mut input: Vec<Elem>) -> Vec<Elem> {
        let remove_idx = rand::rng().random_range(0..input.len());
        remove(input, remove_idx)
    }

    pub fn ensured_shuffle<N: Clone + PartialEq>(input: &[N]) -> Vec<N> {
        assert!(input.len() > 1); // no point shuffling a single element
        let mut new = input.to_vec();
        let mut rng = rand::rng();
        while vectors_equal(&new, input) {
            new.shuffle(&mut rng);
        }
        new
    }

    pub fn ensured_shuffle_keep_first<N: Clone + PartialEq>(input: &Vec<N>) -> Vec<N> {
        assert!(input.len() > 2); // no point shuffling a single element
        let mut new = input.clone();
        new.splice(1.., ensured_shuffle(&new[1..]));
        new
    }
}

pub mod varlists {
    use rand::Rng;
    use sp1_lido_accounting_zk_shared::eth_consensus_layer::VariableList;

    use super::vecs;

    pub fn append<Elem: Clone, Size: typenum::Unsigned>(
        mut input: VariableList<Elem, Size>,
        element: Elem,
    ) -> VariableList<Elem, Size> {
        input.push(element).expect("Error: must not fail");
        input
    }

    pub fn duplicate<Elem: Clone, Size: typenum::Unsigned>(
        mut input: VariableList<Elem, Size>,
        index: usize,
    ) -> VariableList<Elem, Size> {
        let elem = input[index].clone();
        append(input, elem)
    }

    pub fn duplicate_random<Elem: Clone, Size: typenum::Unsigned>(
        mut input: VariableList<Elem, Size>,
    ) -> VariableList<Elem, Size> {
        let duplicate_idx = rand::thread_rng().gen_range(0..input.len());
        duplicate(input, duplicate_idx)
    }

    pub fn modify<Elem: Clone, Size: typenum::Unsigned>(
        mut input: VariableList<Elem, Size>,
        index: usize,
        modifier: fn(Elem) -> Elem,
    ) -> VariableList<Elem, Size> {
        input[index] = modifier(input[index].clone());
        input
    }

    pub fn modify_random<Elem: Clone, Size: typenum::Unsigned>(
        mut input: VariableList<Elem, Size>,
        modifier: fn(Elem) -> Elem,
    ) -> VariableList<Elem, Size> {
        let modify_idx = rand::thread_rng().gen_range(0..input.len());
        modify(input, modify_idx, modifier)
    }

    pub fn remove<Elem: Clone, Size: typenum::Unsigned>(
        mut input: VariableList<Elem, Size>,
        index: usize,
    ) -> VariableList<Elem, Size> {
        let as_vec = input.to_vec();
        vecs::remove(as_vec, index).into()
    }

    pub fn remove_random<Elem: Clone, Size: typenum::Unsigned>(
        mut input: VariableList<Elem, Size>,
    ) -> VariableList<Elem, Size> {
        let remove_idx = rand::thread_rng().gen_range(0..input.len());
        remove(input, remove_idx)
    }

    pub fn ensured_shuffle<Elem: Clone + PartialEq, Size: typenum::Unsigned>(
        input: VariableList<Elem, Size>,
    ) -> VariableList<Elem, Size> {
        let as_vec = input.to_vec();
        vecs::ensured_shuffle(&as_vec).into()
    }

    pub fn ensured_shuffle_keep_first<Elem: Clone + PartialEq, Size: typenum::Unsigned>(
        input: VariableList<Elem, Size>,
    ) -> VariableList<Elem, Size> {
        let mut as_vec = input.to_vec();
        vecs::ensured_shuffle_keep_first(&as_vec).into()
    }
}
