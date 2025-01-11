use anyhow::anyhow;
use lazy_static::lazy_static;
use sp1_lido_accounting_scripts::consts::{self, Network, NetworkInfo, WrappedNetwork};
use sp1_lido_accounting_scripts::sp1_client_wrapper::SP1ClientWrapperImpl;
use sp1_lido_accounting_zk_shared::eth_consensus_layer::Hash256;
use sp1_lido_accounting_zk_shared::io::eth_io::{BeaconChainSlot, ReferenceSlot};
use sp1_sdk::ProverClient;

pub mod env;
pub mod files;
pub mod tampering_bs;

pub static NETWORK: WrappedNetwork = WrappedNetwork::Anvil(Network::Sepolia);
pub const DEPLOY_SLOT: BeaconChainSlot = BeaconChainSlot(5832096);

// TODO: Enable local prover if/when it becomes feasible.
// In short, local proving with groth16 seems to not really work at the moment -
// get stuck at generating proof with ~100% CPU utilization for ~40 minutes.
// This makes local prover impractical - network takes ~5-10 minutes to finish
// #[cfg(not(feature = "test_network_prover"))]
// lazy_static! {
//     pub static ref SP1_CLIENT: SP1ClientWrapperImpl = SP1ClientWrapperImpl::new(ProverClient::local(), ELF);
// }
// #[cfg(feature = "test_network_prover")]
lazy_static! {
    pub static ref SP1_CLIENT: SP1ClientWrapperImpl = SP1ClientWrapperImpl::new(ProverClient::network(), consts::ELF);
}

lazy_static! {
    pub static ref LIDO_CREDS: Hash256 = NETWORK.get_config().lido_withdrawal_credentials.into();
}

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
