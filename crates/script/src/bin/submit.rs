use clap::Parser;
use sp1_lido_accounting_scripts::scripts;
use sp1_lido_accounting_scripts::scripts::prelude::EnvVars;
use sp1_lido_accounting_scripts::tracing as tracing_config;
use sp1_lido_accounting_scripts::utils::read_env;
use sp1_lido_accounting_zk_shared::io::eth_io::ReferenceSlot;

// cargo run --bin submit --release -- --target-slot 5982336 --store --local-verify

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, required = false)]
    target_ref_slot: Option<u64>,
    #[clap(long, required = false)]
    previous_ref_slot: Option<u64>,
    #[clap(long, required = false, default_value = "false")]
    dry_run: bool,
    #[clap(long, required = false, default_value = "false")]
    verify_input: bool,
    #[clap(long, required = false, default_value = "false")]
    verify_proof: bool,
    #[clap(long, required = false, default_value = "false")]
    report_cycles: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // logging setup
    tracing_config::setup_logger(
        tracing_config::LoggingConfig::default()
            .with_thread_names(true)
            .use_format(read_env("LOG_FORMAT", tracing_config::LogFormat::Plain)),
    );

    let args = ProveArgs::parse();
    tracing::debug!("Args: {:?}", args);

    let env_vars = EnvVars::init_from_env_or_crash();

    let script_runtime = scripts::prelude::ScriptRuntime::init(&env_vars)
        .unwrap_or_else(|e| panic!("Failed to initialize script runtime: {e:?}"));

    let flags = scripts::submit::Flags {
        verify_input: args.verify_input,
        verify_proof: args.verify_proof,
        dry_run: args.dry_run,
        report_cycles: args.report_cycles,
    };

    let tx_receipt = scripts::submit::run(
        &script_runtime,
        args.target_ref_slot.map(ReferenceSlot),
        args.previous_ref_slot.map(ReferenceSlot),
        &flags,
    )
    .await?;
    tracing::info!("Report transaction complete {:#?}", tx_receipt.transaction_hash);
    Ok(())
}
