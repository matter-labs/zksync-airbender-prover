use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use zksync_os_snark_prover::{
    generate_verification_key, init_tracing, metrics, run_linking_fri_snark,
};
use zksync_sequencer_proof_client::{SequencerEndpoint, SequencerProofClient};

#[derive(Default, Debug, Serialize, Deserialize, Parser, Clone)]
pub struct SetupOptions {
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
        /// Sequencer URL(s) to poll for tasks. Comma-separated for round-robin.
        ///
        /// Format: http[s]://[username:password@]host:port
        ///
        /// Examples:
        ///   --sequencer-urls http://localhost:3124,https://user1:pass1@sequencer1.com:3124,https://user2:pass2@sequencer2.com
        ///
        /// Credentials are extracted and sent via HTTP Authorization headers.
        #[arg(
            short,
            long,
            alias = "sequencer-url",
            value_delimiter = ',',
            num_args = 1..,
            default_value = "http://localhost:3124"
        )]
        sequencer_urls: Vec<SequencerEndpoint>,
        #[clap(flatten)]
        setup: SetupOptions,
        /// Number of iterations before exiting. Only successfully generated proofs count. If not specified, runs indefinitely
        #[arg(long)]
        iterations: Option<usize>,
        /// Port to run the Prometheus metrics server on
        #[arg(long, default_value = "3124")]
        prometheus_port: u16,
        /// Timeout for HTTP requests to sequencer in seconds. If no response is received within this time, the prover will exit.
        #[arg(long, default_value = "2")]
        request_timeout_secs: u64,
        /// Disable ZK for SNARK proofs
        #[arg(long, default_value_t = false)]
        disable_zk: bool,
        /// Name of the prover for identification in the sequencer
        #[arg(long, default_value = "unknown_prover")]
        prover_name: String,
    },
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();

    // Circuit synthesis (key generation and the SNARK wrapper chain) exhausts the default
    // stack, and the main thread's size is fixed by the OS. Give every thread the runtime
    // spawns (workers and blocking threads alike) an explicit stack size: it only limits
    // how far the stack may grow, nothing is allocated up front. RUST_MIN_STACK, when set,
    // is used as-is (so constrained environments can also lower it); otherwise 256 MiB.
    let stack_size = std::env::var("RUST_MIN_STACK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256 * 1024 * 1024);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(stack_size)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    match cli.command {
        Commands::GenerateKeys {
            setup:
                SetupOptions {
                    output_dir,
                    trusted_setup_file,
                },
            vk_verification_key_file,
        } => {
            // Run synthesis on a runtime-managed thread rather than the OS-sized main one.
            runtime.block_on(async move {
                tokio::task::spawn_blocking(move || {
                    generate_verification_key(
                        output_dir,
                        trusted_setup_file,
                        vk_verification_key_file,
                    )
                })
                .await
                .expect("key generation task panicked")
            })?;
        }
        Commands::RunProver {
            sequencer_urls,
            setup:
                SetupOptions {
                    output_dir,
                    trusted_setup_file,
                },
            iterations,
            prometheus_port,
            request_timeout_secs,
            disable_zk,
            prover_name,
        } => {
            let (stop_sender, stop_receiver) = watch::channel(false);

            runtime.block_on(async move {
                let metrics_handle = tokio::spawn(async move {
                    metrics::start_metrics_exporter(prometheus_port, stop_receiver).await
                });

                let timeout = Duration::from_secs(request_timeout_secs);

                tracing::info!(
                    "Creating {} sequencer proof clients for urls: {:?}",
                    sequencer_urls.len(),
                    sequencer_urls
                );
                let clients =
                    SequencerProofClient::new_clients(sequencer_urls, prover_name, Some(timeout))
                        .expect("failed to create sequencer proof clients");

                tracing::info!(
                    "Starting zksync_os_snark_prover with request timeout of {}s",
                    request_timeout_secs
                );

                // The proving chain is synchronous and stack-hungry; drive it from a
                // runtime blocking thread (which gets the explicit stack size above)
                // rather than polling it on the OS-sized main thread via `block_on`.
                let runtime_handle = tokio::runtime::Handle::current();
                let prover_task = tokio::task::spawn_blocking(move || {
                    runtime_handle.block_on(run_linking_fri_snark(
                        clients,
                        output_dir,
                        trusted_setup_file,
                        iterations,
                        disable_zk,
                    ))
                });

                tokio::select! {
                    result = prover_task => {
                        tracing::info!("SNARK prover finished");
                        result
                            .expect("SNARK prover task panicked")
                            .expect("SNARK prover finished with error");
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

    Ok(())
}
