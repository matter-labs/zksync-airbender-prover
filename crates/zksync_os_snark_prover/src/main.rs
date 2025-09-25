use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use zksync_os_snark_prover::{
    generate_verification_key, init_tracing, metrics, run_linking_fri_snark,
};

#[derive(Default, Debug, Serialize, Deserialize, Parser, Clone)]
pub struct SetupOptions {
    #[arg(long)]
    binary_path: String,

    #[arg(long)]
    output_dir: String,

    #[arg(long)]
    trusted_setup_file: String,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // TODO: redo this command, naming is confusing
    /// Generate the snark verification keys
    GenerateKeys {
        #[clap(flatten)]
        setup: SetupOptions,
        /// Path to the output verification key file
        #[arg(long)]
        vk_verification_key_file: Option<String>,
    },

    RunProver {
        #[arg(short, long)]
        sequencer_url: Option<String>,
        #[clap(flatten)]
        setup: SetupOptions,
        // #[arg(short, long, default_value = "linking-fris")]
        // mode: SnarkMode,
        /// Number of iterations before exiting. Only successfully generated proofs count. If not specified, runs indefinitely
        #[arg(long)]
        iterations: Option<usize>,
        /// Port to run the Prometheus metrics server on
        #[arg(long, default_value = "3124")]
        prometheus_port: u16,
    },
}

fn main() {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys {
            setup:
                SetupOptions {
                    binary_path,
                    output_dir,
                    trusted_setup_file,
                },
            vk_verification_key_file,
        } => generate_verification_key(
            binary_path,
            output_dir,
            trusted_setup_file,
            vk_verification_key_file,
        ),
        Commands::RunProver {
            sequencer_url,
            setup:
                SetupOptions {
                    binary_path,
                    output_dir,
                    trusted_setup_file,
                },
            // mode,
            iterations,
            prometheus_port,
        } => {
            // TODO: edit this comment
            // we need a bigger stack, due to crypto code exhausting default stack size, 40 MBs picked here
            // note that size is not allocated, only limits the amount to which it can grow
            let stack_size = 40 * 1024 * 1024;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .thread_stack_size(stack_size)
                .enable_all()
                .build()
                .expect("failed to build tokio context");

            let (stop_sender, stop_receiver) = watch::channel(false);

            runtime.block_on(async move {
                let metrics_handle = tokio::spawn(async move {
                    metrics::start_metrics_exporter(prometheus_port, stop_receiver).await
                });

                tokio::select! {
                    result = run_linking_fri_snark(
                        binary_path,
                        sequencer_url,
                        output_dir,
                        trusted_setup_file,
                        iterations,
                    ) => {
                        tracing::info!("SNARK prover finished");
                        result.expect("SNARK prover finished with error");
                        stop_sender.send(true).expect("failed to send stop signal");
                    }
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("Stop request received, shutting down");
                    },
                }

                match tokio::time::timeout(Duration::from_secs(10), metrics_handle).await {
                    Ok(join_result) => {
                        if let Err(join_err) = join_result {
                            tracing::warn!("metrics task panicked or was cancelled: {join_err}");
                        }
                    }
                    Err(e) => {
                        tracing::error!("Metrics exporter timed out, aborting: {e}");
                    }
                }
            });
        }
    }
}
