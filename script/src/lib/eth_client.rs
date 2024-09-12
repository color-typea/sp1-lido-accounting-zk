use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolValue;
use sp1_lido_accounting_zk_shared::io::eth_io::{
    conversions, ReportMetadataRust, ReportMetadataSolidity, ReportRust, ReportSolidity,
};
use std::env;
use web3::contract::Options;
use web3::transports::Http;
use web3::types::TransactionReceipt;
use web3::{contract::Contract, types::Address, Web3};

pub struct Sp1LidoAccountingReportContract {
    contract: Contract<Http>,
    sender: Address,
}

// type SubmitReportArgs = (U256, ReportSolidity, ReportMetadataSolidity);
type SubmitReportArgs = (
    u64,
    ReportSolidity,
    //  ReportMetadataRust,
    //   Vec<u8>,
    //    Vec<u8>
);

impl Sp1LidoAccountingReportContract {
    const CONFIRMATIONS: usize = 3;
    pub async fn new(web3: &web3::Web3<web3::transports::Http>, contract_address: Address, sender: Address) -> Self {
        let contract = Contract::from_json(web3.eth(), contract_address, super::CONTRACT_ABI).unwrap();
        Sp1LidoAccountingReportContract { contract, sender }
    }

    pub async fn submit_report_data(
        &self,
        slot: u64,
        report: ReportSolidity,
        metadata: ReportMetadataSolidity,
        proof: Vec<u8>,
        public_values: Vec<u8>,
    ) -> web3::error::Result<TransactionReceipt> {
        let options = Options {
            gas: Some(5_000_000.into()),
            value: None,
            ..Default::default()
        };

        let params: SubmitReportArgs = (slot, report.tokenize());
        self.contract
            .call_with_confirmations("submitReportData", params, self.sender, options, Self::CONFIRMATIONS)
            .await
    }
}

struct EthClient {
    pub web3: Web3<Http>,
}

impl EthClient {
    pub fn new(endpoint_url: &str) -> Self {
        let transport = web3::transports::Http::new(endpoint_url).unwrap();
        let web3 = web3::Web3::new(transport);
        Self { web3 }
    }

    pub fn new_from_env() -> Self {
        let endpoint = env::var("EXECUTION_LAYER_RPC").expect("Failed to read EXECUTION_LAYER_RPC env var");
        Self::new(&endpoint)
    }
}
