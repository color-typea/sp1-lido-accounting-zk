#![allow(dead_code)]
use alloy::{
    eips::eip4788::BEACON_ROOTS_ADDRESS,
    node_bindings::{Anvil, AnvilInstance},
    providers::Provider,
    sol,
};
use alloy_primitives::{Address, U256};
use sp1_lido_accounting_scripts::{
    beacon_state_reader::{
        file::FileBeaconStateWriter, reqwest::CachedReqwestBeaconStateReader, BeaconStateReader, StateId,
    },
    consts::{NetworkConfig, NetworkInfo, WrappedNetwork},
    deploy::prepare_deploy_params,
    eth_client::{
        DefaultProvider, EthELClient, HashConsensusContractWrapper, ProviderFactory,
        Sp1LidoAccountingReportContractWrapper,
    },
    prometheus_metrics::Metrics,
    scripts::{
        self,
        prelude::{
            BeaconStateReaderEnum, EthInfrastructure, Flags, LidoInfrastructure, LidoSettings, Sp1Infrastructure,
        },
    },
    sp1_client_wrapper::{SP1ClientWrapper, SP1ClientWrapperImpl},
};

use hex_literal::hex;
use sp1_lido_accounting_zk_shared::{
    eth_consensus_layer::{BeaconBlockHeader, BeaconState},
    eth_spec,
    io::{
        eth_io::{BeaconChainSlot, HaveSlotWithBlock},
        program_io::WithdrawalVaultData,
    },
};
use sp1_sdk::ProverClient;
use std::{
    env,
    io::{BufRead, BufReader},
    path::PathBuf,
    sync::Arc,
};
use tree_hash::TreeHash;
use typenum::Unsigned;

use crate::test_utils::{self};
use lazy_static::lazy_static;

pub const RETRIES: usize = 3;
const FORWARD_ANVIL_LOGS: bool = true;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    BeaconRootsMock,
    "../../test_contracts/out/BeaconRootsMock.sol/BeaconRootsMock.json",
);

lazy_static! {
    pub static ref METRICS: Arc<Metrics> = Arc::new(Metrics::new("irrelevant"));
}

lazy_static! {
    pub static ref SP1_CLIENT: Arc<SP1ClientWrapperImpl> = {
        tracing::warn!("Initializing SP1 Client");
        Arc::new(SP1ClientWrapperImpl::new(
            ProverClient::from_env(),
            METRICS.services.sp1_client.clone(),
        ))
    };
}

pub struct IntegrationTestEnvironment {
    // When going out of scope, AnvilInstance will terminate the anvil instance it corresponds to,
    // so test env need to assume ownership of anvil instance even if it doesn't use it
    #[allow(dead_code)]
    pub anvil: AnvilInstance,
    pub script_runtime: scripts::prelude::ScriptRuntime,
    pub test_files: test_utils::files::TestFiles,
    file_writer: FileBeaconStateWriter,
    beacon_roots_mock: Option<BeaconRootsMock::BeaconRootsMockInstance<Arc<DefaultProvider>>>,
}

impl IntegrationTestEnvironment {
    pub async fn default() -> anyhow::Result<Self> {
        Self::new(test_utils::NETWORK.clone(), test_utils::DEPLOY_SLOT).await
    }

    fn parse_envs() -> anyhow::Result<(PathBuf, String, String, String, Address, Address)> {
        let file_store_location = PathBuf::from(env::var("BS_FILE_STORE")?);
        let rpc_endpoint = env::var("CONSENSUS_LAYER_RPC")?;
        let bs_endpoint = env::var("BEACON_STATE_RPC")?;
        let fork_url = env::var("INTEGRATION_TEST_FORK_URL")?;
        let verifier_address: Address = env::var("SP1_VERIFIER_ADDRESS")?.parse()?;
        let hash_consensus_address: Address = env::var("HASH_CONSENSUS_ADDRESS")?.parse()?;

        Ok((
            file_store_location,
            rpc_endpoint,
            bs_endpoint,
            fork_url,
            verifier_address,
            hash_consensus_address,
        ))
    }

    async fn start_anvil(
        fork_url: String,
        fork_block_number: u64,
        with_log_capture: bool,
    ) -> anyhow::Result<AnvilInstance> {
        tracing::info!(
            "Starting anvil: fork_block_number={}, fork_url={}",
            fork_block_number,
            fork_url
        );
        let anvil_builder = Anvil::new().fork(fork_url).fork_block_number(fork_block_number);

        let anvil = if with_log_capture {
            let mut anvil = anvil_builder.keep_stdout().try_spawn()?;
            let anvil_child_process = anvil.child_mut();

            if let Some(stdout) = anvil_child_process.stdout.take() {
                let reader_stdout = BufReader::new(stdout);
                std::thread::spawn(move || {
                    for line in reader_stdout.lines().map_while(Result::ok) {
                        println!("[anvil] {line}");
                    }
                });
            }

            if let Some(stderr) = anvil_child_process.stderr.take() {
                let reader_stderr = BufReader::new(stderr);
                std::thread::spawn(move || {
                    for line in reader_stderr.lines().map_while(Result::ok) {
                        println!("[anvil] {line}");
                    }
                });
            }
            anvil
        } else {
            anvil_builder.try_spawn()?
        };
        Ok(anvil)
    }

    pub async fn new(network: WrappedNetwork, deploy_slot: BeaconChainSlot) -> anyhow::Result<Self> {
        let (file_store_location, rpc_endpoint, bs_endpoint, fork_url, verifier_address, hash_consensus_address) =
            Self::parse_envs()?;
        let cached_reader = CachedReqwestBeaconStateReader::new(
            &rpc_endpoint,
            &bs_endpoint,
            &file_store_location,
            METRICS.services.beacon_state_client.clone(),
        )?;
        let beacon_state_reader = Arc::new(BeaconStateReaderEnum::RPCCached(cached_reader));
        let file_writer =
            FileBeaconStateWriter::new(&file_store_location, METRICS.services.beacon_state_client.clone())?;

        let target_slot = Self::finalized_slot(Arc::clone(&beacon_state_reader)).await?;
        let finalized_bs =
            Self::read_latest_bs_at_or_before(Arc::clone(&beacon_state_reader), target_slot, RETRIES).await?;

        let fork_block_number = finalized_bs.latest_execution_payload_header.block_number + 2;

        let anvil = Self::start_anvil(fork_url, fork_block_number, FORWARD_ANVIL_LOGS).await?;

        tracing::info!("Initializing Eth client");
        let provider = Arc::new(ProviderFactory::create_provider(
            anvil.keys()[0].clone(),
            anvil.endpoint().parse()?,
        ));
        let eth_client = EthELClient::new(Arc::clone(&provider), METRICS.services.eth_client.clone());

        let test_files = test_utils::files::TestFiles::new_from_manifest_dir();
        let deploy_bs: BeaconState = test_files
            .read_beacon_state(&StateId::Slot(deploy_slot))
            .await
            .map_err(test_utils::eyre_to_anyhow)?;

        // Sepolia values
        let withdrawal_vault_address = hex!("De7318Afa67eaD6d6bbC8224dfCe5ed6e4b86d76").into();
        let withdrawal_credentials = hex!("010000000000000000000000De7318Afa67eaD6d6bbC8224dfCe5ed6e4b86d76").into();

        let vkey = SP1_CLIENT.vk_bytes()?;

        let deploy_params = prepare_deploy_params(
            vkey,
            &deploy_bs,
            &network,
            verifier_address,
            withdrawal_vault_address,
            withdrawal_credentials,
            [1; 20].into(),
        );

        tracing::info!("Deploying contract with parameters {:?}", deploy_params);
        let report_contract = Sp1LidoAccountingReportContractWrapper::deploy(Arc::clone(&provider), &deploy_params)
            .await
            .map_err(test_utils::eyre_to_anyhow)?;

        let hash_consensus_contract = HashConsensusContractWrapper::new(
            Arc::clone(&provider),
            hash_consensus_address,
            METRICS.services.hash_consensus.clone(),
        );

        let lido_settings = LidoSettings {
            contract_address: report_contract.address().to_owned(),
            withdrawal_vault_address,
            withdrawal_credentials,
            hash_consensus_address,
        };

        tracing::info!("Deployed contract at {}", report_contract.address());

        let script_runtime = scripts::prelude::ScriptRuntime::new(
            EthInfrastructure {
                network,
                provider,
                eth_client,
                beacon_state_reader,
            },
            Sp1Infrastructure {
                sp1_client: Arc::clone(&SP1_CLIENT),
            },
            LidoInfrastructure {
                report_contract,
                hash_consensus_contract,
            },
            lido_settings,
            Arc::clone(&METRICS),
            Flags {
                dry_run: false,
                report_cycles: false,
            },
        );

        let instance = Self {
            anvil, // this needs to be here so that test executor assumes ownership of running anvil instance - otherwise it terminates right away
            script_runtime,
            test_files: test_utils::files::TestFiles::new_from_manifest_dir(),
            file_writer,
            beacon_roots_mock: None,
        };

        Ok(instance)
    }

    pub fn network_config(&self) -> NetworkConfig {
        self.script_runtime.network().get_config()
    }

    pub async fn finalized_slot(bs_reader: Arc<impl BeaconStateReader>) -> anyhow::Result<BeaconChainSlot> {
        let finalized_block_header = bs_reader.read_beacon_block_header(&StateId::Finalized).await?;
        Ok(finalized_block_header.bc_slot())
    }

    pub async fn get_finalized_slot(&self) -> anyhow::Result<BeaconChainSlot> {
        Self::finalized_slot(self.script_runtime.bs_reader()).await
    }

    pub async fn get_balance_proof(&self, state_id: &StateId) -> anyhow::Result<WithdrawalVaultData> {
        let address = self.script_runtime.lido_settings.withdrawal_vault_address;
        let bs: BeaconState = self.read_beacon_state(state_id).await?;
        let execution_layer_block_hash = bs.latest_execution_payload_header.block_hash;
        let withdrawal_vault_data = self
            .script_runtime
            .eth_infra
            .eth_client
            .get_withdrawal_vault_data(address, execution_layer_block_hash)
            .await?;
        Ok(withdrawal_vault_data)
    }

    pub async fn read_beacon_block_header(&self, state_id: &StateId) -> anyhow::Result<BeaconBlockHeader> {
        self.script_runtime.bs_reader().read_beacon_block_header(state_id).await
    }

    pub async fn read_beacon_state(&self, state_id: &StateId) -> anyhow::Result<BeaconState> {
        self.script_runtime.bs_reader().read_beacon_state(state_id).await
    }

    pub async fn stub_state(&self, beacon_state: &BeaconState, block_header: &BeaconBlockHeader) -> anyhow::Result<()> {
        let state_hash = beacon_state.tree_hash_root();
        assert_eq!(beacon_state.slot, block_header.slot);
        assert_eq!(state_hash, block_header.state_root);

        self.file_writer.write_beacon_state(beacon_state)?;
        self.file_writer.write_beacon_block_header(block_header)?;

        self.record_hash(block_header).await?;
        Ok(())
    }

    pub async fn record_hash(&self, block_header: &BeaconBlockHeader) -> anyhow::Result<()> {
        if let Some(beacon_roots_mock) = &self.beacon_roots_mock {
            let slot = block_header.slot;
            let timestamp = self.network_config().genesis_block_timestamp + (slot * eth_spec::SecondsPerSlot::to_u64());
            let beacon_block_hash = block_header.tree_hash_root();
            tracing::debug!("Stubbing block hash for {slot}@{timestamp} = {beacon_block_hash:#?}");

            let _set_root_tx = beacon_roots_mock
                .setRoot(U256::from(timestamp), block_header.tree_hash_root())
                .send()
                .await?
                .get_receipt()
                .await?;
            tracing::info!(
                "Stubbed state for slot {slot}, block_root: {:#?}, state_root: {:#?}",
                beacon_block_hash,
                block_header.state_root
            );
        }
        Ok(())
    }

    pub async fn mock_beacon_state_roots_contract(&mut self) -> anyhow::Result<()> {
        tracing::info!("Replacing BEACON_STATE_ROOTS contract bytecode");
        let provider = Arc::clone(&self.script_runtime.eth_infra.provider);
        let _res: () = provider
            .raw_request(
                "anvil_setCode".into(),
                [BEACON_ROOTS_ADDRESS.to_string(), BeaconRootsMock::BYTECODE.to_string()],
            )
            .await?;
        let beacon_roots_mock_instance = BeaconRootsMock::new(BEACON_ROOTS_ADDRESS, provider);

        self.beacon_roots_mock = Some(beacon_roots_mock_instance);
        Ok(())
    }

    pub async fn read_latest_bs_at_or_before(
        bs_reader: Arc<impl BeaconStateReader>,
        slot: BeaconChainSlot,
        retries: usize,
    ) -> anyhow::Result<BeaconState> {
        let step = eth_spec::SlotsPerEpoch::to_u64();
        let mut attempt = 0;
        let mut current_slot = slot;
        loop {
            tracing::debug!("Fetching beacon state: attempt {attempt}, target slot {current_slot}");
            let try_bs = bs_reader.read_beacon_state(&StateId::Slot(current_slot)).await;

            if let Ok(beacon_state) = try_bs {
                break Ok(beacon_state);
            } else if attempt > retries {
                break try_bs;
            } else {
                attempt += 1;
                current_slot = BeaconChainSlot(current_slot.0 - step);
            }
        }
    }
}
