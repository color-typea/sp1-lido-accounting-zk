use alloy::node_bindings::{anvil, Anvil, AnvilInstance};
use alloy_sol_types::SolType;
use anyhow::Context;
use sp1_lido_accounting_scripts::{
    beacon_state_reader::{BeaconStateReader, BeaconStateReaderEnum, StateId},
    consts::{self, NetworkInfo, WrappedNetwork},
    eth_client::{self, Contract, EthELClient, ProviderFactory, Sp1LidoAccountingReportContractWrapper},
    proof_storage::StoredProof,
    scripts::{self, shared as shared_logic},
    sp1_client_wrapper::{SP1ClientWrapper, SP1ClientWrapperImpl},
};

use lazy_static::lazy_static;
use sp1_lido_accounting_zk_shared::{
    eth_consensus_layer::{BeaconState, Hash256},
    io::{
        eth_io::{BeaconChainSlot, PublicValuesRust, PublicValuesSolidity, ReportMetadataRust, ReportRust},
        program_io::WithdrawalVaultData,
    },
};
use sp1_sdk::{HashableKey, ProverClient};
use std::{env, sync::Arc};
use test_utils::TestFiles;
use thiserror::Error;
mod test_utils;
use hex_literal::hex;

static NETWORK: &WrappedNetwork = &test_utils::NETWORK;
const STORED_PROOF_FILE_NAME: &str = "fixture.json";

lazy_static! {
    static ref SP1_CLIENT: SP1ClientWrapperImpl = SP1ClientWrapperImpl::new(ProverClient::network(), consts::ELF);
    static ref LIDO_CREDS: Hash256 = NETWORK.get_config().lido_withdrawal_credentials.into();
}

#[derive(Debug, Error)]
enum ExecutorError {
    #[error("Contract rejected: {0:#?}")]
    Contract(eth_client::Error),
    #[error("Failed o launch anvil: {0:#?}")]
    AnvilLaunch(anvil::AnvilError),
    #[error("Eyre error: {0:#?}")]
    Eyre(eyre::Error),
    #[error("Anyhow error: {0:#?}")]
    Anyhow(anyhow::Error),
}

type Result<T> = std::result::Result<T, ExecutorError>;
type TestExecutorResult = Result<alloy_primitives::TxHash>;

impl From<eth_client::Error> for ExecutorError {
    fn from(value: eth_client::Error) -> Self {
        ExecutorError::Contract(value)
    }
}

impl From<anvil::AnvilError> for ExecutorError {
    fn from(value: anvil::AnvilError) -> Self {
        ExecutorError::AnvilLaunch(value)
    }
}

impl From<eyre::Error> for ExecutorError {
    fn from(value: eyre::Error) -> Self {
        ExecutorError::Eyre(value)
    }
}

impl From<anyhow::Error> for ExecutorError {
    fn from(value: anyhow::Error) -> Self {
        ExecutorError::Anyhow(value)
    }
}

struct TestExecutor<M: Fn(PublicValuesRust) -> PublicValuesRust> {
    bs_reader: BeaconStateReaderEnum,
    client: &'static SP1ClientWrapperImpl,
    test_files: test_utils::TestFiles,
    tamper_public_values: M,
}

impl<M: Fn(PublicValuesRust) -> PublicValuesRust> TestExecutor<M> {
    fn new(tamper_public_values: M) -> Self {
        let test_files = TestFiles::new_from_manifest_dir();
        Self {
            bs_reader: BeaconStateReaderEnum::new_from_env(NETWORK),
            client: &SP1_CLIENT,
            test_files,
            tamper_public_values,
        }
    }

    fn get_stored_proof(&self) -> Result<StoredProof> {
        let proof = self.test_files.read_proof(STORED_PROOF_FILE_NAME)?;
        Ok(proof)
    }

    async fn start_anvil(&self, target_slot: BeaconChainSlot) -> Result<AnvilInstance> {
        let finalized_bs =
            test_utils::read_latest_bs_at_or_before(&self.bs_reader, target_slot, test_utils::RETRIES).await?;
        let fork_url =
            env::var("INTEGRATION_TEST_FORK_URL").expect("INTEGRATION_TEST_FORK_URL env var must be specified");
        let fork_block_number = finalized_bs.latest_execution_payload_header.block_number + 2;
        log::debug!(
            "Starting anvil: fork_block_number={}, fork_url={}",
            fork_block_number,
            fork_url
        );
        let anvil = Anvil::new()
            .fork(fork_url)
            .fork_block_number(fork_block_number)
            .try_spawn()?;
        Ok(anvil)
    }

    async fn deploy_contract(
        &self,
        network: &impl NetworkInfo,
        anvil: &AnvilInstance,
    ) -> Result<(EthELClient, Contract)> {
        let endpoint = anvil
            .endpoint()
            .parse()
            .context("Failed to parse anvil endpoint as url")?;
        let provider = ProviderFactory::create_provider(anvil.keys()[0].clone(), endpoint);
        let prov = Arc::new(provider);

        let deploy_bs: BeaconState = self
            .test_files
            .read_beacon_state(&StateId::Slot(test_utils::DEPLOY_SLOT))
            .await?;
        let deploy_params = scripts::deploy::prepare_deploy_params(self.client.vk_bytes(), &deploy_bs, network);

        log::info!("Deploying contract with parameters {:?}", deploy_params);
        let contract = Sp1LidoAccountingReportContractWrapper::deploy(Arc::clone(&prov), &deploy_params).await?;
        let eth_client = EthELClient::new(Arc::clone(&prov));
        log::info!("Deployed contract at {}", contract.address());
        Ok((eth_client, contract))
    }

    async fn run_test(&self) -> TestExecutorResult {
        sp1_sdk::utils::setup_logger();
        let lido_withdrawal_credentials: Hash256 = NETWORK.get_config().lido_withdrawal_credentials.into();
        let stored_proof = self.get_stored_proof()?;

        let reference_slot = stored_proof.report.reference_slot;
        let bc_slot = stored_proof.metadata.bc_slot;

        // // Anvil needs to be here in scope for the duration of the test, otherwise it terminates
        // // Hence creating it here (i.e. owner is this function) and passing down to deploy conract
        let anvil = self.start_anvil(bc_slot).await?;
        let (_eth_client, contract) = self.deploy_contract(NETWORK, &anvil).await?;
        let previous_slot = contract.get_latest_validator_state_slot().await?;

        let target_bh = self.bs_reader.read_beacon_block_header(&StateId::Slot(bc_slot)).await?;
        let target_bs = self.bs_reader.read_beacon_state(&StateId::Slot(bc_slot)).await?;
        // Should read old state from untampered reader, so the old state compute will match
        let old_bs = self.bs_reader.read_beacon_state(&StateId::Slot(previous_slot)).await?;
        log::info!("Preparing program input");

        let withdrawal_vault_data = WithdrawalVaultData {
            balance: stored_proof.metadata.withdrawal_vault_data.balance,
            vault_address: stored_proof.metadata.withdrawal_vault_data.vault_address,
            account_proof: vec![vec![0u8, 1u8, 2u8, 3u8]], // proof is unused in this scenario
        };

        let (_program_input, public_values) = shared_logic::prepare_program_input(
            reference_slot,
            &target_bs,
            &target_bh,
            &old_bs,
            &lido_withdrawal_credentials,
            withdrawal_vault_data,
            false,
        );
        log::info!("Reading proof");

        let tampered_public_values = (self.tamper_public_values)(public_values);

        let pub_vals_solidity: PublicValuesSolidity = tampered_public_values.into();
        let public_values_bytes: Vec<u8> = PublicValuesSolidity::abi_encode(&pub_vals_solidity);

        log::info!("Sending report");
        let result = contract
            .submit_report_data(stored_proof.proof, public_values_bytes)
            .await?;

        Ok(result)
    }
}

/*
General idea here is that a valid proof is used with a mismatching report

Report:
* Different slot
* Different cl balance
* Different deposited validator count
* Different exited validator count

Metatada:
* Different slot
* Different epoch
* Different Lido withdrawal credentials
* Different beacon block hash
* Different old state - slot
* Different old state - hash
* Different new state - slot
* Different new state - hash

Withdrawal credentials:
* Different address
* Actual proof, tampered balance
*/

fn id<T>(val: T) -> T {
    val
}

fn wrap_report_mapper(mapper: fn(ReportRust) -> ReportRust) -> impl Fn(PublicValuesRust) -> PublicValuesRust {
    move |pub_vals| {
        let mut new_pub_values = pub_vals.clone();
        new_pub_values.report = (mapper)(new_pub_values.report);
        new_pub_values
    }
}

fn wrap_metadata_mapper(
    mapper: fn(ReportMetadataRust) -> ReportMetadataRust,
) -> impl Fn(PublicValuesRust) -> PublicValuesRust {
    move |pub_vals| {
        let mut new_pub_values = pub_vals.clone();
        new_pub_values.metadata = (mapper)(new_pub_values.metadata);
        new_pub_values
    }
}

fn assert_rejects(result: TestExecutorResult) -> Result<()> {
    match result {
        Err(ExecutorError::Contract(eth_client::Error::Rejection(err))) => {
            log::info!("As expected, contract rejected {:#?}", err);
            Ok(())
        }
        Err(ExecutorError::Contract(eth_client::Error::CustomRejection(err))) => {
            log::info!("As expected, verifier rejected {:#?}", err);
            Ok(())
        }
        Err(other_err) => Err(other_err),
        Ok(_txhash) => Err(ExecutorError::Anyhow(anyhow::anyhow!("Report accepted"))),
    }
}

#[test]
fn check_vkey_matches() -> Result<()> {
    let test_files = test_utils::TestFiles::new_from_manifest_dir();
    let proof = test_files.read_proof(STORED_PROOF_FILE_NAME)?;
    assert_eq!(SP1_CLIENT.vk().bytes32(), proof.vkey, "Vkey in stored proof and in client mismatch. Please run write_test_fixture script to generate new stored proof");
    Ok(())
}

#[test]
fn check_old_slot_matches() -> Result<()> {
    let test_files = test_utils::TestFiles::new_from_manifest_dir();
    let proof = test_files.read_proof(STORED_PROOF_FILE_NAME)?;
    assert_eq!(
        test_utils::DEPLOY_SLOT,
        proof.metadata.state_for_previous_report.slot,
        "Stored proof targets wrong previous slot, should be {}, got {}",
        test_utils::DEPLOY_SLOT,
        proof.metadata.state_for_previous_report.slot
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_sanity_check_should_pass() -> Result<()> {
    let executor = TestExecutor::new(id);

    let result = executor.run_test().await;
    match result {
        Ok(_txhash) => {
            log::info!("Sanity check succeeded - submitting valid report with no tampering succeeds");
            Ok(())
        }
        Err(err) => Err(err),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_report_slot() -> Result<()> {
    let executor = TestExecutor::new(wrap_report_mapper(|report| {
        let mut new_report = report.clone();
        new_report.reference_slot = new_report.reference_slot - 1;
        new_report
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_report_slot2() -> Result<()> {
    let executor = TestExecutor::new(wrap_report_mapper(|report| {
        let mut new_report = report.clone();
        new_report.reference_slot = new_report.reference_slot + 10;
        new_report
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_report_cl_balance() -> Result<()> {
    let executor = TestExecutor::new(wrap_report_mapper(|report| {
        let mut new_report = report.clone();
        new_report.lido_cl_balance += 50;
        new_report
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_report_deposited_count() -> Result<()> {
    let executor = TestExecutor::new(wrap_report_mapper(|report| {
        let mut new_report = report.clone();
        new_report.deposited_lido_validators += 1;
        new_report
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_report_exited_count() -> Result<()> {
    let executor = TestExecutor::new(wrap_report_mapper(|report| {
        let mut new_report = report.clone();
        new_report.exited_lido_validators += 1;
        new_report
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_metadata_slot() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.bc_slot = new_metadata.bc_slot - 10;
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_metadata_slot2() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.bc_slot = new_metadata.bc_slot + 10;
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_metadata_epoch() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.epoch = 9876543;
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_metadata_withdrawal_credentials() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.lido_withdrawal_credentials =
            hex!("010000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd");
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_metadata_beacon_block_hash() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.beacon_block_hash = hex!("123456789000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd");
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_metadata_old_state_slot() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.state_for_previous_report.slot = new_metadata.state_for_previous_report.slot - 10;
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_metadata_old_state_merkle_root() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.state_for_previous_report.merkle_root =
            hex!("1234567890000000000000000000000000000000000000000000000000000000");
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_metadata_new_state_slot() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.new_state.slot = new_metadata.new_state.slot + 10;
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_metadata_new_state_merkle_root() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.new_state.merkle_root = hex!("1234567890000000000000000000000000000000000000000000000000000000");
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_withdrawal_wrong_address() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.withdrawal_vault_data.vault_address = hex!("1234567890000000000000000000000000000000").into();
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}

#[tokio::test(flavor = "multi_thread")]
async fn report_tampering_withdrawal_wrong_balance() -> Result<()> {
    let executor = TestExecutor::new(wrap_metadata_mapper(|metadata| {
        let mut new_metadata = metadata.clone();
        new_metadata.withdrawal_vault_data.balance = alloy_primitives::U256::from(1234567890u64);
        new_metadata
    }));

    assert_rejects(executor.run_test().await)
}
