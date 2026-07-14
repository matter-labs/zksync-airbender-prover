use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD, Engine as _};

use clap::Parser;
use protocol_version::SupportedProtocolVersions;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use zksync_airbender_cli::prover_utils::{
    serialize_to_file, ProgramProver, ProgramProverConfig, ProgramSource, ProofTarget,
};
use zksync_airbender_execution_utils::unrolled::UnrolledProgramProof;
use zksync_sequencer_proof_client::{
    FriJobInputs, ProofClient, SequencerEndpoint, SequencerProofClient,
};

use crate::metrics::FRI_PROVER_METRICS;

pub mod metrics;

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
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
        alias = "base-url",
        value_delimiter = ',',
        num_args = 1..,
        default_value = "http://localhost:3124"
    )]
    pub sequencer_urls: Vec<SequencerEndpoint>,
    /// Path to `app.bin`
    #[arg(long)]
    pub app_bin_path: Option<PathBuf>,
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

    /// Name of the prover for identification in the sequencer's prover api
    #[arg(long, default_value = "unknown_prover")]
    pub prover_name: String,
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

/// Create a new prover for the given program binary.
///
/// The prover holds all precomputed setup data (and, with the `gpu` feature, the GPU
/// context), so it should be constructed once and reused across batches.
pub fn create_prover(binary_path: &Path) -> anyhow::Result<ProgramProver> {
    let source = ProgramSource::from_paths(
        binary_path
            .to_str()
            .with_context(|| format!("non-UTF8 binary path {binary_path:?}"))?
            .to_string(),
        // The matching `.text` section path is derived from the `.bin` path.
        None,
    );
    // Fail fast on a bad path instead of erroring only when the first job is picked.
    for path in [&source.bin_path, &source.text_path] {
        anyhow::ensure!(Path::new(path).is_file(), "program file not found: {path}");
    }
    let config = ProgramProverConfig {
        // Recursion up to the unified layer: the compact form expected by the SNARK wrapper.
        target: ProofTarget::RecursionUnified,
        ..Default::default()
    };
    ProgramProver::new(source, config).map_err(|e| anyhow::anyhow!("failed to create prover: {e}"))
}

pub fn create_proof(
    prover: &ProgramProver,
    batch_id: u64,
    prover_input: Vec<u32>,
) -> anyhow::Result<UnrolledProgramProof> {
    let artifact = prover
        .prove_words(batch_id, prover_input)
        .map_err(|e| anyhow::anyhow!("failed to prove batch {batch_id}: {e}"))?;
    Ok(artifact.proof)
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(args.request_timeout_secs);

    tracing::info!(
        "Creating {} sequencer proof clients for urls: {:?}",
        args.sequencer_urls.len(),
        args.sequencer_urls
    );

    let clients =
        SequencerProofClient::new_clients(args.sequencer_urls, args.prover_name, Some(timeout))
            .context("failed to create sequencer proof clients")?;

    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };

    let supported_versions = SupportedProtocolVersions::default();
    tracing::info!("{:#?}", supported_versions);

    let binary_path = args
        .app_bin_path
        .unwrap_or_else(|| Path::new(&manifest_path).join("../../multiblock_batch.bin"));
    let prover = create_prover(&binary_path)?;

    tracing::info!(
        "Starting Zksync OS FRI prover with request timeout of {}s",
        args.request_timeout_secs
    );

    let mut proof_count = 0;

    let mut retrying_since = Instant::now();

    let retry_interval = Duration::from_millis(100);
    // If no proof is generated for 10 seconds, log a message
    let retry_log_interval = Duration::from_secs(10);

    // Cycle through clients in round-robin fashion
    for client in clients.iter().cycle() {
        tracing::debug!("Polling sequencer: {}", client.sequencer_url());

        let proof_generated = run_inner(
            client.as_ref(),
            &prover,
            args.path.clone(),
            &supported_versions,
        )
        .await
        .expect("Failed to run FRI prover");

        if proof_generated {
            proof_count += 1;

            // Check if we've reached the iteration limit
            if let Some(max_proofs_generated) = args.iterations {
                if proof_count >= max_proofs_generated {
                    tracing::info!(
                        "Reached maximum iterations ({max_proofs_generated}), exiting...",
                    );
                    return Ok(());
                }
            }
            retrying_since = Instant::now();
        } else {
            // If no task was found, wait before trying again

            if retrying_since.elapsed() >= retry_log_interval {
                tracing::info!(
                    "No pending batches to prove from sequencer for {} seconds",
                    retrying_since.elapsed().as_secs()
                );
                retrying_since = Instant::now();
            }
            tracing::debug!(
                "No pending batches to prove from sequencer, retrying in {} ms",
                retry_interval.as_millis()
            );
            tokio::time::sleep(retry_interval).await;
        }
    }

    Ok(())
}

pub async fn run_inner(
    client: &dyn ProofClient,
    prover: &ProgramProver,
    path: Option<PathBuf>,
    supported_versions: &SupportedProtocolVersions,
) -> anyhow::Result<bool> {
    let FriJobInputs {
        batch_number,
        vk_hash,
        prover_input,
    } = match client.pick_fri_job().await {
        Err(err) => {
            // Check if the error is a timeout error
            if err
                .downcast_ref::<reqwest::Error>()
                .map(|e| e.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout waiting for response from sequencer {}: {err}",
                    client.sequencer_url()
                );
                tracing::error!("Exiting prover due to timeout");
                FRI_PROVER_METRICS.timeout_errors.inc();
                return Ok(false);
            }
            tracing::error!(
                "Error fetching next prover job from sequencer {}: {err}",
                client.sequencer_url()
            );
            return Ok(false);
        }
        Ok(Some(fri_job_input)) => {
            if !supported_versions.contains(&fri_job_input.vk_hash) {
                tracing::error!(
                    "Unsupported protocol version with vk_hash: {} for batch number {} from sequencer {}",
                    fri_job_input.vk_hash,
                    fri_job_input.batch_number,
                    client.sequencer_url()
                );
                return Ok(false);
            }
            fri_job_input
        }

        Ok(None) => {
            tracing::debug!(
                "No pending batches to prove from sequencer {}",
                client.sequencer_url()
            );
            return Ok(false);
        }
    };

    let started_at = Instant::now();

    // make prover_input (Vec<u8>) into Vec<u32>, rejecting malformed input instead of
    // silently truncating trailing bytes:
    anyhow::ensure!(
        prover_input.len() % 4 == 0,
        "prover input for batch {batch_number} has {} bytes, expected a multiple of 4",
        prover_input.len()
    );
    let prover_input: Vec<u32> = prover_input
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();

    tracing::info!(
        "Starting proving batch number {} with vk hash {} from sequencer {}",
        batch_number,
        vk_hash,
        client.sequencer_url()
    );

    let proof = create_proof(prover, batch_number as u64, prover_input)?;

    tracing::info!(
        "Finished proving batch number {} with vk hash {}",
        batch_number,
        vk_hash
    );

    let proof_bytes: Vec<u8> = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .expect("failed to bincode-serialize proof");

    // 2) base64-encode that binary blob
    let proof_b64 = STANDARD.encode(&proof_bytes);

    if let Some(ref path) = path {
        serialize_to_file(&proof_b64, path);
    }

    FRI_PROVER_METRICS
        .latest_proven_batch
        .set(batch_number as i64);

    let proof_time = started_at.elapsed().as_secs_f64();

    FRI_PROVER_METRICS.time_taken.observe(proof_time);

    match client
        .submit_fri_proof(batch_number, vk_hash.clone(), proof_b64)
        .await
    {
        Ok(_) => {
            tracing::info!(
                "Successfully submitted proof for batch number {} with vk hash {} to sequencer {}, generated in {} seconds",
                batch_number,
                vk_hash,
                client.sequencer_url(),
                proof_time
            );
            Ok(true)
        }
        Err(err) => {
            // Check if the error is a timeout error
            if err
                .downcast_ref::<reqwest::Error>()
                .map(|e| e.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout submitting proof for batch number {} with vk hash {} to sequencer {}: {}",
                    batch_number,
                    vk_hash,
                    client.sequencer_url(),
                    err
                );
                tracing::error!("Exiting prover due to timeout");
                FRI_PROVER_METRICS.timeout_errors.inc();
            } else {
                tracing::error!(
                    "Failed to submit proof for batch number {} with vk hash {} to sequencer {}: {}",
                    batch_number,
                    vk_hash,
                    client.sequencer_url(),
                    err
                );
            }
            Ok(false)
        }
    }
}
