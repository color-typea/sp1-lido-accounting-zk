use clap::Parser;
use sp1_lido_accounting_dev_scripts::scripts as dev_scripts;
use sp1_lido_accounting_scripts::{
    consts::NetworkInfo,
    scripts::{self, prelude::EnvVars},
    tracing as tracing_config,
    utils::read_env,
};
use sp1_lido_accounting_zk_shared::io::eth_io::ReferenceSlot;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ExecuteArgs {
    #[clap(long)]
    target_ref_slot: u64,
    #[clap(long)]
    previous_ref_slot: Option<u64>,
}

#[tokio::main]
async fn main() {
    // logging setup
    tracing_config::setup_logger(
        tracing_config::LoggingConfig::default()
            .with_thread_names(true)
            .use_format(read_env("LOG_FORMAT", tracing_config::LogFormat::Plain)),
    );
    let args = ExecuteArgs::parse();
    tracing::debug!("Args: {:?}", args);

    let env_vars = EnvVars::init_from_env_or_crash();

    let script_runtime = scripts::prelude::ScriptRuntime::init(&env_vars)
        .expect("Failed to initialize script runtime");

    let main_span =
        tracing::info_span!("main", network = script_runtime.network().as_str()).entered();

    tracing::info!(
        "Running for network {:?}, slot: {}, previous_slot: {:?}",
        script_runtime.network().as_str(),
        args.target_ref_slot,
        args.previous_ref_slot
    );

    dev_scripts::execute::run(
        &script_runtime,
        ReferenceSlot(args.target_ref_slot),
        args.previous_ref_slot.map(ReferenceSlot),
    )
    .await
    .expect("Failed to run `execute");

    main_span.exit();
}
