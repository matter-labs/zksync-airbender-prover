use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use clap::Parser;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use zksync_airbender_cli::prover_utils::{
    create_proofs_internal, create_recursion_proofs, load_binary_from_path, serialize_to_file,
    GpuSharedState,
};
use zksync_airbender_execution_utils::{Machine, ProgramProof, RecursionStrategy};
use zksync_sequencer_proof_client::{sequencer_proof_client::SequencerProofClient, ProofClient};

use crate::metrics::FRI_PROVER_METRICS;

pub mod metrics;

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// Base URL for the proof-data server (e.g., "http://<IP>:<PORT>")
    #[arg(short, long, default_value = "http://localhost:3124")]
    pub base_url: String,
    /// Enable logging and use the logging-enabled binary
    /// This is not used in the FRI prover, but is kept for backward compatibility.
    #[arg(long)]
    pub enabled_logging: bool,
    /// Path to `app.bin`
    #[arg(long)]
    pub app_bin_path: Option<PathBuf>,
    /// Circuit limit - max number of MainVM circuits to instantiate to run the block fully
    #[arg(long, default_value = "10000")]
    pub circuit_limit: usize,
    /// Number of iterations before exiting. Only successfully generated proofs count. If not specified, runs indefinitely
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Port to run the Prometheus metrics server on
    #[arg(long, default_value = "3124")]
    pub prometheus_port: u16,

    /// Timeout for HTTP requests to sequencer in seconds. If no response is received within this time, the prover will exit.
    #[arg(long, default_value = "2")]
    pub request_timeout_secs: u64,
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

pub fn create_proof(
    prover_input: Vec<u32>,
    binary: &Vec<u32>,
    circuit_limit: usize,
    _gpu_state: &mut GpuSharedState,
) -> ProgramProof {
    let mut timing = Some(0f64);
    let (proof_list, proof_metadata) = create_proofs_internal(
        binary,
        prover_input,
        &Machine::Standard,
        circuit_limit,
        None,
        #[cfg(feature = "gpu")]
        &mut Some(_gpu_state),
        #[cfg(not(feature = "gpu"))]
        &mut None,
        &mut timing, // timing info
    );
    let (recursion_proof_list, recursion_proof_metadata) = create_recursion_proofs(
        proof_list,
        proof_metadata,
        // This is the default strategy (where recursion is done on reduced machine, and final step on 23 machine).
        RecursionStrategy::UseReducedLog23Machine,
        &None,
        #[cfg(feature = "gpu")]
        &mut Some(_gpu_state),
        #[cfg(not(feature = "gpu"))]
        &mut None,
        &mut timing, // timing info
    );

    ProgramProof::from_proof_list_and_metadata(&recursion_proof_list, &recursion_proof_metadata)
}

pub async fn run(args: Args) {
    use std::time::Duration;

    let timeout = Duration::from_secs(args.request_timeout_secs);
    let client = SequencerProofClient::new_with_timeout(args.base_url, Some(timeout));

    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };
    let binary_path = args
        .app_bin_path
        .unwrap_or_else(|| Path::new(&manifest_path).join("../../multiblock_batch.bin"));
    let binary = load_binary_from_path(&binary_path.to_str().unwrap().to_string());
    // For regular fri proving, we keep using reduced RiscV machine.
    #[cfg(feature = "gpu")]
    let mut gpu_state = GpuSharedState::new(
        &binary,
        zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
    );
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = GpuSharedState::new(&binary);

    tracing::info!(
        "Starting Zksync OS FRI prover for {} with request timeout of {}s",
        client.sequencer_url(),
        args.request_timeout_secs
    );

    let mut proof_count = 0;

    loop {
        let proof_generated = run_inner(
            &client,
            &binary,
            args.circuit_limit,
            &mut gpu_state,
            args.path.clone(),
        )
        .await
        .expect("Failed to run FRI prover");

        proof_count += proof_generated as usize;

        // Check if we've reached the iteration limit
        if let Some(max_proofs_generated) = args.iterations {
            if proof_count >= max_proofs_generated {
                tracing::info!("Reached maximum iterations ({max_proofs_generated}), exiting...",);
                break;
            }
        }
    }
}

pub async fn run_inner<P: ProofClient>(
    client: &P,
    binary: &Vec<u32>,
    circuit_limit: usize,
    #[cfg(feature = "gpu")] gpu_state: &mut GpuSharedState,
    #[cfg(not(feature = "gpu"))] gpu_state: &mut GpuSharedState<'_>,
    path: Option<PathBuf>,
) -> anyhow::Result<bool> {
    let (block_number, prover_input) = match client.pick_fri_job().await {
        Err(err) => {
            // Check if the error is a timeout error
            if err
                .downcast_ref::<reqwest::Error>()
                .map(|e| e.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!("Timeout waiting for response from sequencer: {err}");
                tracing::error!("Exiting prover due to timeout");
                FRI_PROVER_METRICS.timeout_errors.inc();
                return Ok(false);
            }
            tracing::error!("Error fetching next prover job: {err}");
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            return Ok(false);
        }
        Ok(Some(next_block)) => next_block,
        Ok(None) => {
            tracing::info!("No pending blocks to prove, retrying in 100ms...");
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            return Ok(false);
        }
    };

    let started_at = Instant::now();

    // make prover_input (Vec<u8>) into Vec<u32>:
    let prover_input: Vec<u32> = prover_input
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();

    tracing::info!("Starting proving block number {}", block_number);

    let proof = create_proof(prover_input, binary, circuit_limit, gpu_state);

    tracing::info!("Finished proving block number {}", block_number);
    let proof_bytes: Vec<u8> = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .expect("failed to bincode-serialize proof");

    // 2) base64-encode that binary blob
    let proof_b64 = STANDARD.encode(&proof_bytes);

    if let Some(ref path) = path {
        serialize_to_file(&proof_b64, path);
    }

    FRI_PROVER_METRICS
        .latest_proven_block
        .set(block_number as i64);

    FRI_PROVER_METRICS
        .time_taken
        .observe(started_at.elapsed().as_secs_f64());

    match client.submit_fri_proof(block_number, proof_b64).await {
        Ok(_) => tracing::info!(
            "Successfully submitted proof for block number {}",
            block_number
        ),
        Err(err) => {
            // Check if the error is a timeout error
            if err
                .downcast_ref::<reqwest::Error>()
                .map(|e| e.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout submitting proof for block number {}: {}",
                    block_number,
                    err
                );
                tracing::error!("Exiting prover due to timeout");
                FRI_PROVER_METRICS.timeout_errors.inc();
            }
            tracing::error!(
                "Failed to submit proof for block number {}: {}",
                block_number,
                err
            );
        }
    }

    Ok(true)
}
