// TODO!: This code base should be moved in a single binary.
// SNARK & FRI should be libs only and expose no binaries themselves.
// We'll need slightly more "involved" CLI args, but nothing too complex.
use std::{
    future::Future,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Context;
use clap::Parser;
use protocol_version::SupportedProtocolVersions;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
#[cfg(feature = "gpu")]
use zkos_wrapper::gpu::snark::gpu_create_snark_setup_data;
use zksync_airbender_cli::prover_utils::load_binary_from_path;
#[cfg(not(feature = "gpu"))]
use zksync_airbender_cli::prover_utils::GpuSharedState;
#[cfg(feature = "gpu")]
use zksync_airbender_cli::prover_utils::GpuSharedState;
use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
#[cfg(feature = "gpu")]
use zksync_os_snark_prover::compute_compression_vk;
use zksync_sequencer_proof_client::{JobQueueStage, SequencerEndpoint, SequencerProofClient};

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// Max SNARK latency in seconds (default value - 1 hour)
    #[arg(long, default_value = "3600", conflicts_with = "max_fris_per_snark")]
    pub max_snark_latency: Option<u64>,
    /// Max amount of FRI proofs per SNARK (default value - 100)
    #[arg(long, default_value = "100", conflicts_with = "max_snark_latency")]
    pub max_fris_per_snark: Option<usize>,
    // SYSCOIN
    /// SYSCOIN Switch to SNARK early when any sequencer has this many queued SNARK jobs. Set to 0 to disable.
    #[arg(long, default_value = "80")]
    pub adaptive_snark_queue_threshold: usize,
    /// SYSCOIN Max time to wait for a SNARK job after switching away from FRI proving
    #[arg(long, default_value = "120")]
    pub snark_acquire_timeout_secs: u64,
    /// Sequencer URL(s) for polling tasks. Comma-separated for round-robin.
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
    /// Circuit limit - max number of MainVM circuits to instantiate to run the batch fully
    #[arg(long, default_value = "10000")]
    pub circuit_limit: usize,
    /// Directory to store the output files for SNARK prover
    #[arg(long)]
    pub output_dir: String,
    /// Path to the trusted setup file for SNARK prover
    #[arg(long)]
    pub trusted_setup_file: String,
    /// Number of iterations before exiting. Only successfully generated SNARK proofs count. If not specified, runs indefinitely
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file for FRI proofs
    #[arg(short, long)]
    pub fri_path: Option<PathBuf>,
    /// Disable ZK for SNARK proofs
    #[arg(long, default_value_t = false)]
    pub disable_zk: bool,
}

const SNARK_POLL_INTERVAL: Duration = Duration::from_secs(1);

async fn acquire_snark_proof<F, Fut>(
    snark_acquire_timeout: Duration,
    poll_interval: Duration,
    mut run_snark_attempt: F,
) -> anyhow::Result<bool>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    let started_at = Instant::now();
    loop {
        if run_snark_attempt().await? {
            return Ok(true);
        }

        if started_at.elapsed() >= snark_acquire_timeout {
            return Ok(false);
        }

        tokio::time::sleep(poll_interval).await;
    }
}
// SYSCOIN
async fn ordered_fri_client_indices(
    clients: &[Box<dyn zksync_sequencer_proof_client::ProofClient + Send + Sync>],
) -> Vec<usize> {
    let mut scored: Vec<(usize, bool, u64, u32)> = Vec::new();
    for (idx, client) in clients.iter().enumerate() {
        let Ok(statuses) = client.status(JobQueueStage::Fri).await else {
            continue;
        };
        let best_unassigned = statuses
            .iter()
            .filter(|s| s.assigned_seconds_ago.is_none())
            .max_by_key(|s| s.added_seconds_ago)
            .map(|s| (true, s.added_seconds_ago, s.batch_number));
        let best_any = statuses
            .iter()
            .max_by_key(|s| s.added_seconds_ago)
            .map(|s| (false, s.added_seconds_ago, s.batch_number));

        let Some(best) = best_unassigned.or(best_any) else {
            continue;
        };
        scored.push((idx, best.0, best.1, best.2));
    }
    scored.sort_by_key(|(idx, is_unassigned, age, batch)| {
        (!*is_unassigned, std::cmp::Reverse(*age), *batch, *idx)
    });
    scored.into_iter().map(|(idx, _, _, _)| idx).collect()
}

async fn ordered_client_indices_for_stage(
    clients: &[Box<dyn zksync_sequencer_proof_client::ProofClient + Send + Sync>],
    stage: JobQueueStage,
) -> Vec<usize> {
    let mut scored: Vec<(usize, bool, u64, u32)> = Vec::new();
    for (idx, client) in clients.iter().enumerate() {
        let Some(best) = client.status(stage).await.ok().and_then(|statuses| {
            let best_unassigned = statuses
                .iter()
                .filter(|s| s.assigned_seconds_ago.is_none())
                .max_by_key(|s| s.added_seconds_ago)
                .map(|s| (true, s.added_seconds_ago, s.batch_number));
            let best_any = statuses
                .iter()
                .max_by_key(|s| s.added_seconds_ago)
                .map(|s| (false, s.added_seconds_ago, s.batch_number));

            best_unassigned.or(best_any)
        }) else {
            continue;
        };
        scored.push((idx, best.0, best.1, best.2));
    }
    scored.sort_by_key(|(idx, is_unassigned, age, batch)| {
        (!*is_unassigned, std::cmp::Reverse(*age), *batch, *idx)
    });
    scored.into_iter().map(|(idx, _, _, _)| idx).collect()
}

// SYSCOIN
async fn snark_queue_pressure(
    clients: &[Box<dyn zksync_sequencer_proof_client::ProofClient + Send + Sync>],
    threshold: usize,
) -> Option<(usize, usize, usize, u64)> {
    if threshold == 0 {
        return None;
    }

    let mut best: Option<(usize, usize, usize, u64)> = None;
    for (idx, client) in clients.iter().enumerate() {
        let Ok(statuses) = client.status(JobQueueStage::Snark).await else {
            continue;
        };
        let total = statuses.len();
        if total < threshold {
            continue;
        }

        let unassigned = statuses
            .iter()
            .filter(|status| status.assigned_seconds_ago.is_none())
            .count();
        let oldest_seconds = statuses
            .iter()
            .map(|status| status.added_seconds_ago)
            .max()
            .unwrap_or_default();

        let candidate = (idx, total, unassigned, oldest_seconds);
        let replace_best = match best.as_ref() {
            Some(current) => candidate.1 > current.1 || candidate.3 > current.3,
            None => true,
        };
        if replace_best {
            best = Some(candidate);
        }
    }

    best
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    tracing::info!(
        "Creating {} sequencer proof clients for urls: {:?}",
        args.sequencer_urls.len(),
        args.sequencer_urls
    );
    let clients =
        SequencerProofClient::new_clients(args.sequencer_urls, "prover_service".to_string(), None)
            .context("failed to create sequencer proof clients")?;

    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };
    let binary_path = args
        .app_bin_path
        .unwrap_or_else(|| Path::new(&manifest_path).join("../../multiblock_batch.bin"));
    let binary = load_binary_from_path(&binary_path.to_str().unwrap().to_string());
    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    let supported_versions = SupportedProtocolVersions::default();
    tracing::info!("{:#?}", supported_versions);

    #[cfg(feature = "gpu")]
    let precomputations = {
        tracing::info!("Computing SNARK precomputations");
        let compression_vk = compute_compression_vk(binary_path.to_str().unwrap().to_string());
        let precomputations =
            gpu_create_snark_setup_data(&compression_vk, &args.trusted_setup_file);
        tracing::info!("Finished computing SNARK precomputations");
        precomputations
    };

    tracing::info!("Starting Zksync OS Prover Service");
    // SYSCOIN
    let mut snark_proof_count = 0;
    let mut snark_latency = Instant::now();
    let mut fri_proof_count = 0usize;
    let retry_interval = Duration::from_millis(100);

    #[cfg(feature = "gpu")]
    let mut gpu_state = Some(GpuSharedState::new(
        &binary,
        zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
    ));
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = GpuSharedState::new(&binary);

    loop {
        // Run FRI until one of the configured handoff conditions is met.
        loop {
            let ordered_indices = ordered_fri_client_indices(&clients).await;
            if ordered_indices.is_empty() {
                tokio::time::sleep(retry_interval).await;
                if let Some(max_snark_latency) = args.max_snark_latency {
                    if snark_latency.elapsed().as_secs() >= max_snark_latency {
                        tracing::info!(
                            "SNARK latency reached max_snark_latency ({max_snark_latency} seconds), switching to SNARK phase"
                        );
                        break;
                    }
                }
                // SYSCOIN
                if let Some((client_idx, total, unassigned, oldest_seconds)) =
                    snark_queue_pressure(&clients, args.adaptive_snark_queue_threshold).await
                {
                    tracing::info!(
                        sequencer_url = %clients[client_idx].sequencer_url(),
                        total,
                        unassigned,
                        oldest_seconds,
                        threshold = args.adaptive_snark_queue_threshold,
                        "SNARK queue pressure reached adaptive threshold, switching to SNARK phase"
                    );
                    break;
                }
                continue;
            }

            let mut proof_generated = false;
            for client_idx in ordered_indices {
                let client = &clients[client_idx];

                if zksync_os_fri_prover::run_inner(
                    client.as_ref(),
                    &binary,
                    args.circuit_limit,
                    #[cfg(feature = "gpu")]
                    gpu_state
                        .as_mut()
                        .expect("FRI GPU state should be initialized"),
                    #[cfg(not(feature = "gpu"))]
                    &mut gpu_state,
                    args.fri_path.clone(),
                    &supported_versions,
                )
                .await
                .expect("Failed to run FRI prover")
                {
                    proof_generated = true;
                    break;
                }
            }

            fri_proof_count += proof_generated as usize;
            if !proof_generated {
                tokio::time::sleep(retry_interval).await;
            }

            if let Some(max_snark_latency) = args.max_snark_latency {
                if snark_latency.elapsed().as_secs() >= max_snark_latency {
                    tracing::info!(
                        "SNARK latency reached max_snark_latency ({max_snark_latency} seconds), switching to SNARK phase"
                    );
                    break;
                }
            }
            // SYSCOIN
            if let Some((client_idx, total, unassigned, oldest_seconds)) =
                snark_queue_pressure(&clients, args.adaptive_snark_queue_threshold).await
            {
                tracing::info!(
                    sequencer_url = %clients[client_idx].sequencer_url(),
                    total,
                    unassigned,
                    oldest_seconds,
                    threshold = args.adaptive_snark_queue_threshold,
                    "SNARK queue pressure reached adaptive threshold, switching to SNARK phase"
                );
                break;
            }
            if let Some(max_fris_per_snark) = args.max_fris_per_snark {
                if fri_proof_count >= max_fris_per_snark {
                    tracing::info!(
                        "FRI proof count reached max_fris_per_snark ({max_fris_per_snark}), switching to SNARK phase"
                    );
                    break;
                }
            }
        }

        #[cfg(feature = "gpu")]
        {
            tracing::info!("Dropping FRI GPU state before SNARK phase");
            // Release FRI GPU allocations before SNARK merge/final proof to reduce peak VRAM usage.
            gpu_state = None;
        }

        let proof_generated = acquire_snark_proof(
            Duration::from_secs(args.snark_acquire_timeout_secs),
            SNARK_POLL_INTERVAL,
            || async {
                let ordered_indices =
                    ordered_client_indices_for_stage(&clients, JobQueueStage::Snark).await;
                for idx in ordered_indices {
                    let client = &clients[idx];
                    if zksync_os_snark_prover::run_inner(
                        client.as_ref(),
                        &verifier_binary,
                        args.output_dir.clone(),
                        args.trusted_setup_file.clone(),
                        #[cfg(feature = "gpu")]
                        &precomputations,
                        args.disable_zk,
                        &supported_versions,
                    )
                    .await
                    .expect("Failed to run SNARK prover")
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            },
        )
        .await
        .expect("Failed to run SNARK prover");

        if proof_generated {
            tracing::info!("Successfully generated a SNARK proof");
            snark_proof_count += 1;
        } else {
            tracing::info!(
                "No SNARK proof was generated within snark_acquire_timeout_secs ({} seconds), returning to FRI phase",
                args.snark_acquire_timeout_secs
            );
        }

        #[cfg(feature = "gpu")]
        {
            tracing::info!("Reinitializing FRI GPU state after SNARK phase");
            gpu_state = Some(GpuSharedState::new(
                &binary,
                zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
            ));
        }

        // Reset phase counters.
        snark_latency = Instant::now();
        fri_proof_count = 0;

        if let Some(max_iterations) = args.iterations {
            if snark_proof_count >= max_iterations {
                tracing::info!("Reached maximum iterations ({max_iterations}), exiting...");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use async_trait::async_trait;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use url::Url;
    use zkos_wrapper::SnarkWrapperProof;
    use zksync_sequencer_proof_client::{
        FriJobInputs, L2BatchNumber, ProofClient, QueueJobStatus, SnarkProofInputs,
    };

    use super::*;

    enum MockStatusResponse {
        Error(anyhow::Error),
        Statuses(Vec<QueueJobStatus>),
    }

    struct MockProofClient {
        url: Url,
        status_response: MockStatusResponse,
    }

    impl MockProofClient {
        fn error(url: &str) -> Self {
            Self {
                url: Url::parse(url).expect("valid url"),
                status_response: MockStatusResponse::Error(anyhow!("status unavailable")),
            }
        }

        fn statuses(url: &str, statuses: Vec<QueueJobStatus>) -> Self {
            Self {
                url: Url::parse(url).expect("valid url"),
                status_response: MockStatusResponse::Statuses(statuses),
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
            match &self.status_response {
                MockStatusResponse::Error(err) => Err(anyhow!("{err}")),
                MockStatusResponse::Statuses(statuses) => Ok(statuses.clone()),
            }
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
    async fn snark_acquire_times_out_instead_of_looping_forever() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_closure = attempts.clone();

        let acquired = tokio::time::timeout(
            Duration::from_millis(100),
            acquire_snark_proof(
                Duration::from_millis(20),
                Duration::from_millis(1),
                move || {
                    let attempts = attempts_for_closure.clone();
                    async move {
                        attempts.fetch_add(1, Ordering::Relaxed);
                        Ok(false)
                    }
                },
            ),
        )
        .await
        .expect("snark acquisition should time out rather than loop forever")
        .expect("snark acquisition should not error");

        assert!(!acquired);
        assert!(attempts.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn ordered_snark_clients_skip_unreachable_and_empty_queues_but_keep_assigned() {
        let clients: Vec<Box<dyn ProofClient + Send + Sync>> = vec![
            Box::new(MockProofClient::error("http://down.local")),
            Box::new(MockProofClient::statuses("http://empty.local", vec![])),
            Box::new(MockProofClient::statuses(
                "http://assigned-only.local",
                vec![QueueJobStatus {
                    batch_number: 20,
                    vk_hash: "vk-assigned".to_owned(),
                    added_seconds_ago: 30,
                    assigned_seconds_ago: Some(1_000),
                    assigned_to_prover_id: Some("other-prover".to_owned()),
                    current_attempt: 2,
                }],
            )),
            Box::new(MockProofClient::statuses(
                "http://healthy-a.local",
                vec![QueueJobStatus {
                    batch_number: 12,
                    vk_hash: "vk-a".to_owned(),
                    added_seconds_ago: 10,
                    assigned_seconds_ago: None,
                    assigned_to_prover_id: None,
                    current_attempt: 0,
                }],
            )),
            Box::new(MockProofClient::statuses(
                "http://healthy-b.local",
                vec![QueueJobStatus {
                    batch_number: 3,
                    vk_hash: "vk-b".to_owned(),
                    added_seconds_ago: 20,
                    assigned_seconds_ago: None,
                    assigned_to_prover_id: None,
                    current_attempt: 0,
                }],
            )),
        ];

        let ordered = ordered_client_indices_for_stage(&clients, JobQueueStage::Snark).await;

        assert_eq!(ordered, vec![4, 3, 2]);
    }

    #[tokio::test]
    // SYSCOIN
    async fn snark_queue_pressure_uses_largest_busy_queue() {
        let clients: Vec<Box<dyn ProofClient + Send + Sync>> = vec![
            Box::new(MockProofClient::statuses(
                "http://below-threshold.local",
                vec![QueueJobStatus {
                    batch_number: 1,
                    vk_hash: "vk-a".to_owned(),
                    added_seconds_ago: 10,
                    assigned_seconds_ago: None,
                    assigned_to_prover_id: None,
                    current_attempt: 0,
                }],
            )),
            Box::new(MockProofClient::statuses(
                "http://busy.local",
                (0..3)
                    .map(|idx| QueueJobStatus {
                        batch_number: 10 + idx,
                        vk_hash: "vk-b".to_owned(),
                        added_seconds_ago: 20 + idx as u64,
                        assigned_seconds_ago: None,
                        assigned_to_prover_id: None,
                        current_attempt: 0,
                    })
                    .collect(),
            )),
        ];

        assert_eq!(snark_queue_pressure(&clients, 0).await, None);
        assert_eq!(snark_queue_pressure(&clients, 4).await, None);
        assert_eq!(snark_queue_pressure(&clients, 3).await, Some((1, 3, 3, 22)));
    }
}
