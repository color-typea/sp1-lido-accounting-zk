use std::path::PathBuf;

use clap::Parser;

use sp1_lido_accounting_scripts::consts::NetworkInfo;
use sp1_lido_accounting_scripts::scripts;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value = "5800000")]
    target_slot: u64,
    #[clap(long, default_value = "5000000")]
    previous_slot: u64,
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    let args = ProveArgs::parse();
    log::debug!("Args: {:?}", args);

    let (network, client, bs_reader) = scripts::prelude::initialize();
    log::info!(
        "Running for network {:?}, slot: {}, previous_slot: {}",
        network,
        args.target_slot,
        args.previous_slot
    );

    let fixture_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/test/fixtures/fixture.json");

    scripts::write_test_fixture::run(
        client,
        bs_reader,
        args.target_slot,
        args.previous_slot,
        &network.get_config().lido_withdrawal_credentials,
        fixture_file.as_path(),
    )
    .await
    .expect("Failed to run `write_test_fixture");
}
