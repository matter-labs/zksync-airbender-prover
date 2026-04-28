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
    create_proofs_internal, create_recursion_proofs, load_binary_from_path, serialize_to_file,
    GpuSharedState,
};
use zksync_airbender_execution_utils::{Machine, ProgramProof, RecursionStrategy};
use zksync_sequencer_proof_client::{
    FriJobInputs, JobQueueStage, ProofClient, QueueJobStatus, SequencerEndpoint,
    SequencerProofClient,
};

use crate::metrics::FRI_PROVER_METRICS;

pub mod metrics;
// SYSCOIN
fn head_queue_job(statuses: &[QueueJobStatus]) -> Option<(bool, u64, u32)> {
    let head_unassigned = statuses
        .iter()
        .filter(|s| s.assigned_seconds_ago.is_none())
        .min_by_key(|s| s.batch_number)
        .map(|s| (true, s.added_seconds_ago, s.batch_number));
    let head_any = statuses
        .iter()
        .min_by_key(|s| s.batch_number)
        .map(|s| (false, s.added_seconds_ago, s.batch_number));

    head_unassigned.or(head_any)
}

async fn ordered_fri_client_indices(clients: &[Box<dyn ProofClient + Send + Sync>]) -> Vec<usize> {
    let mut scored: Vec<(usize, bool, u64, u32)> = Vec::new();
    for (idx, client) in clients.iter().enumerate() {
        let Ok(statuses) = client.status(JobQueueStage::Fri).await else {
            continue;
        };

        let Some(best) = head_queue_job(&statuses) else {
            continue;
        };
        scored.push((idx, best.0, best.1, best.2));
    }

    scored.sort_by_key(|(idx, is_unassigned, age, batch)| {
        (!*is_unassigned, std::cmp::Reverse(*age), *batch, *idx)
    });
    scored.into_iter().map(|(idx, _, _, _)| idx).collect()
}

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
    /// Enable logging and use the logging-enabled binary
    /// This is not used in the FRI prover, but is kept for backward compatibility.
    #[arg(long)]
    pub enabled_logging: bool,
    /// Path to `app.bin`
    #[arg(long)]
    pub app_bin_path: Option<PathBuf>,
    /// Circuit limit - max number of MainVM circuits to instantiate to run the batch fully
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
    #[arg(long, default_value = "30")]
    pub request_timeout_secs: u64,

    /// Name of the prover for identification in the sequencer's prover api
    #[arg(long, default_value = "unknown_prover")]
    pub prover_name: String,
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
        "Starting Zksync OS FRI prover with request timeout of {}s",
        args.request_timeout_secs
    );

    let mut proof_count = 0;

    let mut retrying_since = Instant::now();

    let retry_interval = Duration::from_millis(100);
    // If no proof is generated for 10 seconds, log a message
    let retry_log_interval = Duration::from_secs(10);
    // SYSCOIN
    loop {
        let ordered_indices = ordered_fri_client_indices(&clients).await;
        if ordered_indices.is_empty() {
            if retrying_since.elapsed() >= retry_log_interval {
                tracing::info!(
                    "No visible FRI jobs across sequencers for {} seconds",
                    retrying_since.elapsed().as_secs()
                );
                retrying_since = Instant::now();
            }
            tokio::time::sleep(retry_interval).await;
            continue;
        }
        let mut proof_generated = false;
        for client_idx in ordered_indices {
            let client = &clients[client_idx];
            tracing::debug!("Polling sequencer: {}", client.sequencer_url());

            if run_inner(
                client.as_ref(),
                &binary,
                args.circuit_limit,
                &mut gpu_state,
                args.path.clone(),
                &supported_versions,
            )
            .await
            .expect("Failed to run FRI prover")
            {
                proof_generated = true;
                break;
            }
        }

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
                    "No FRI jobs available for pick from sequencer set for {} seconds",
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
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use url::Url;
    use zksync_sequencer_proof_client::{
        L2BatchNumber, QueueJobStatus, SnarkProofInputs, SnarkWrapperProof,
    };

    use super::*;

    struct MockProofClient {
        url: Url,
        statuses: Vec<QueueJobStatus>,
    }

    impl MockProofClient {
        fn statuses(url: &str, statuses: Vec<QueueJobStatus>) -> Self {
            Self {
                url: Url::parse(url).expect("valid url"),
                statuses,
            }
        }
    }

    #[async_trait]
    impl ProofClient for MockProofClient {
        fn sequencer_url(&self) -> &Url {
            &self.url
        }

        async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
            Ok(None)
        }

        async fn submit_fri_proof(
            &self,
            _batch_number: u32,
            _vk_hash: String,
            _proof: String,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn status(&self, _stage: JobQueueStage) -> anyhow::Result<Vec<QueueJobStatus>> {
            Ok(self.statuses.clone())
        }

        async fn fri_status(&self) -> anyhow::Result<Vec<QueueJobStatus>> {
            self.status(JobQueueStage::Fri).await
        }

        async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
            Ok(None)
        }

        async fn submit_snark_proof(
            &self,
            _from_batch_number: L2BatchNumber,
            _to_batch_number: L2BatchNumber,
            _vk_hash: String,
            _proof: SnarkWrapperProof,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn ordered_fri_clients_score_by_head_batch_age() {
        let clients: Vec<Box<dyn ProofClient + Send + Sync>> = vec![
            Box::new(MockProofClient::statuses(
                "http://old-tail.local",
                vec![
                    QueueJobStatus {
                        batch_number: 1,
                        vk_hash: "vk-head".to_owned(),
                        added_seconds_ago: 10,
                        assigned_seconds_ago: None,
                        assigned_to_prover_id: None,
                        current_attempt: 0,
                    },
                    QueueJobStatus {
                        batch_number: 100,
                        vk_hash: "vk-tail".to_owned(),
                        added_seconds_ago: 10_000,
                        assigned_seconds_ago: None,
                        assigned_to_prover_id: None,
                        current_attempt: 0,
                    },
                ],
            )),
            Box::new(MockProofClient::statuses(
                "http://older-head.local",
                vec![QueueJobStatus {
                    batch_number: 2,
                    vk_hash: "vk-other".to_owned(),
                    added_seconds_ago: 20,
                    assigned_seconds_ago: None,
                    assigned_to_prover_id: None,
                    current_attempt: 0,
                }],
            )),
        ];

        let ordered = ordered_fri_client_indices(&clients).await;

        assert_eq!(ordered, vec![1, 0]);
    }
}

pub async fn run_inner(
    client: &dyn ProofClient,
    binary: &Vec<u32>,
    circuit_limit: usize,
    #[cfg(feature = "gpu")] gpu_state: &mut GpuSharedState,
    #[cfg(not(feature = "gpu"))] gpu_state: &mut GpuSharedState<'_>,
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

    // make prover_input (Vec<u8>) into Vec<u32>:
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

    let proof = create_proof(prover_input, binary, circuit_limit, gpu_state);

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
