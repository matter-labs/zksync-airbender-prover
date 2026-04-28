#[cfg(feature = "gpu")]
use proof_compression::serialization::PlonkSnarkVerifierCircuitDeviceSetupWrapper;
use protocol_version::SupportedProtocolVersions;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing_subscriber::{EnvFilter, FmtSubscriber};
#[cfg(feature = "gpu")]
use zkos_wrapper::{
    generate_risk_wrapper_vk,
    gpu::{compression::get_compression_setup, snark::gpu_create_snark_setup_data},
    BoojumWorker, CompressionVK, SnarkWrapperVK,
};
use zkos_wrapper::{prove, serialize_to_file, SnarkWrapperProof};
use zksync_airbender_cli::prover_utils::{
    create_final_proofs_from_program_proof, create_proofs_internal, GpuSharedState,
};
use zksync_airbender_execution_utils::{
    generate_oracle_data_for_universal_verifier, generate_oracle_data_from_metadata_and_proof_list,
    get_padded_binary, Machine, ProgramProof, RecursionStrategy, VerifierCircuitsIdentifiers,
    UNIVERSAL_CIRCUIT_VERIFIER,
};
use zksync_sequencer_proof_client::JobQueueStage;
use zksync_sequencer_proof_client::{ProofClient, QueueJobStatus, SnarkProofInputs};

use crate::metrics::{SnarkProofTimeStats, SnarkStage, SNARK_PROVER_METRICS};

pub mod metrics;
// SYSCOIN
fn configured_snark_thread_stack_size() -> Option<usize> {
    let raw = std::env::var("RUST_MIN_STACK").ok()?;
    match raw.parse::<usize>() {
        Ok(0) => {
            tracing::warn!("RUST_MIN_STACK is set to 0, ignoring dedicated SNARK thread stack");
            None
        }
        Ok(size) => Some(size),
        Err(error) => {
            tracing::warn!(
                "failed to parse RUST_MIN_STACK='{}' for dedicated SNARK thread stack: {}",
                raw,
                error
            );
            None
        }
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send + 'static>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_owned(),
            Err(_) => "unknown panic payload".to_owned(),
        },
    }
}
// SYSCOIN
fn head_queue_job(statuses: &[QueueJobStatus]) -> Option<(u64, u32)> {
    statuses
        .iter()
        .filter(|s| s.assigned_seconds_ago.is_none())
        .min_by_key(|s| s.batch_number)
        .map(|s| (s.added_seconds_ago, s.batch_number))
}

async fn order_clients_by_oldest_unassigned(
    clients: &[Box<dyn ProofClient + Send + Sync>],
    stage: JobQueueStage,
) -> Vec<usize> {
    let mut scored: Vec<(usize, u64, u32)> = Vec::new();
    for (idx, client) in clients.iter().enumerate() {
        let best = client
            .status(stage)
            .await
            .ok()
            .and_then(|statuses| head_queue_job(&statuses))
            .unwrap_or((0, u32::MAX));
        scored.push((idx, best.0, best.1));
    }

    // Oldest first. Tie-break by lower batch number, then index for deterministic order.
    scored.sort_by_key(|(idx, age, batch)| {
        (
            std::cmp::Reverse(*age),
            *batch,
            *idx, // deterministic stable tie-break
        )
    });
    scored.into_iter().map(|(idx, _, _)| idx).collect()
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

pub fn generate_verification_key(
    binary_path: String,
    output_dir: String,
    trusted_setup_file: String,
    vk_verification_key_file: Option<String>,
) {
    match zkos_wrapper::generate_vk(
        Some(binary_path),
        output_dir,
        Some(trusted_setup_file),
        true,
        zksync_airbender_execution_utils::RecursionStrategy::UseReducedLog23Machine,
    ) {
        Ok(key) => {
            if let Some(vk_file) = vk_verification_key_file {
                std::fs::write(vk_file, format!("{key:?}"))
                    .expect("Failed to write verification key to file");
            } else {
                tracing::info!("Verification key generated successfully: {:#?}", key);
            }
        }
        Err(e) => {
            tracing::error!("Error generating keys: {e}");
        }
    }
}

pub fn merge_fris(
    snark_proof_input: SnarkProofInputs,
    verifier_binary: &Vec<u32>,
    gpu_state: &mut Option<&mut GpuSharedState>,
) -> ProgramProof {
    SNARK_PROVER_METRICS
        .fri_proofs_merged
        .set(snark_proof_input.fri_proofs.len() as i64);

    if snark_proof_input.fri_proofs.len() == 1 {
        tracing::info!("No proof merging needed, only one proof provided");
        return snark_proof_input.fri_proofs[0].clone();
    }
    tracing::info!("Starting proof merging");

    let mut proof = snark_proof_input.fri_proofs[0].clone();
    for i in 1..snark_proof_input.fri_proofs.len() {
        let up_to_batch = snark_proof_input.from_batch_number.0 + i as u32 - 1;
        let curr_batch = snark_proof_input.from_batch_number.0 + i as u32;
        tracing::info!(
            "Linking proofs up to {} with proof for batch {}",
            up_to_batch,
            curr_batch
        );
        let second_proof = snark_proof_input.fri_proofs[i].clone();

        let (first_metadata, first_proof_list) = proof.to_metadata_and_proof_list();
        let (second_metadata, second_proof_list) = second_proof.to_metadata_and_proof_list();

        let first_oracle =
            generate_oracle_data_from_metadata_and_proof_list(&first_metadata, &first_proof_list);
        let second_oracle =
            generate_oracle_data_from_metadata_and_proof_list(&second_metadata, &second_proof_list);

        let mut merged_input = vec![VerifierCircuitsIdentifiers::CombinedRecursionLayers as u32];
        merged_input.extend(first_oracle);
        merged_input.extend(second_oracle);

        let (mut current_proof_list, mut proof_metadata) = create_proofs_internal(
            verifier_binary,
            merged_input,
            &zksync_airbender_execution_utils::Machine::Reduced,
            100, // Guessing - FIXME!!
            Some(first_metadata.create_prev_metadata()),
            gpu_state,
            &mut Some(0f64),
        );
        // Let's do recursion.
        let mut recursion_level = 0;

        while current_proof_list.reduced_proofs.len() > 2 {
            tracing::info!("Recursion step {} after fri merging", recursion_level);
            recursion_level += 1;
            let non_determinism_data =
                generate_oracle_data_for_universal_verifier(&proof_metadata, &current_proof_list);

            (current_proof_list, proof_metadata) = create_proofs_internal(
                verifier_binary,
                non_determinism_data,
                &Machine::Reduced,
                proof_metadata.total_proofs(),
                Some(proof_metadata.create_prev_metadata()),
                gpu_state,
                &mut Some(0f64),
            );
        }

        proof = ProgramProof::from_proof_list_and_metadata(&current_proof_list, &proof_metadata);
        tracing::info!("Finished linking proofs up to batch {}", up_to_batch);
    }

    // TODO: We can do a recursion step here as well, IIUC
    tracing::info!(
        "Finishing linking all proofs from {} to {}",
        snark_proof_input.from_batch_number,
        snark_proof_input.to_batch_number
    );
    proof
}

#[cfg(feature = "gpu")]
pub fn compute_compression_vk(binary_path: String) -> CompressionVK {
    let worker = BoojumWorker::new();

    let risc_wrapper_vk = generate_risk_wrapper_vk(
        Some(binary_path),
        true,
        RecursionStrategy::UseReducedLog23Machine,
        &worker,
    )
    .unwrap();

    let (_, compression_vk, _) = get_compression_setup(&worker, risc_wrapper_vk);
    compression_vk
}

pub async fn run_linking_fri_snark(
    _binary_path: String,
    clients: Vec<Box<dyn ProofClient + Send + Sync>>,
    output_dir: String,
    trusted_setup_file: String,
    iterations: Option<usize>,
    disable_zk: bool,
) -> anyhow::Result<()> {
    let startup_started_at = Instant::now();

    tracing::info!(
        "Initializing SNARK prover with {} sequencer(s):",
        clients.len()
    );
    for client in clients.iter() {
        tracing::info!("  - {}", client.sequencer_url());
    }

    let supported_versions = SupportedProtocolVersions::default();
    tracing::info!("{:#?}", supported_versions);

    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    #[cfg(feature = "gpu")]
    let precomputations = {
        tracing::info!("Computing SNARK precomputations");
        let compression_vk = compute_compression_vk(_binary_path);
        let precomputations = gpu_create_snark_setup_data(&compression_vk, &trusted_setup_file);
        tracing::info!("Finished computing SNARK precomputations");
        precomputations
    };

    SNARK_PROVER_METRICS
        .time_taken_startup
        .observe(startup_started_at.elapsed().as_secs_f64());

    let mut proof_count = 0;

    // SYSCOIN
    loop {
        let mut proof_generated = false;
        let client_order = order_clients_by_oldest_unassigned(&clients, JobQueueStage::Snark).await;

        for idx in client_order {
            let client = &clients[idx];
            tracing::debug!("Polling sequencer: {}", client.sequencer_url());

            if run_inner(
                client.as_ref(),
                &verifier_binary,
                output_dir.clone(),
                trusted_setup_file.clone(),
                #[cfg(feature = "gpu")]
                &precomputations,
                disable_zk,
                &supported_versions,
            )
            .await
            .expect("Failed to run SNARK prover")
            {
                proof_generated = true;
                break;
            }
        }

        if proof_generated {
            proof_count += 1;

            if let Some(max_proofs_generated) = iterations {
                if proof_count >= max_proofs_generated {
                    tracing::info!(
                        "Reached maximum iterations ({max_proofs_generated}), exiting..."
                    );
                    return Ok(());
                }
            }
        } else {
            tracing::info!("No pending SNARK jobs from sequencer set, retrying in 5s...");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

pub async fn run_inner(
    client: &dyn ProofClient,
    verifier_binary: &Vec<u32>,
    output_dir: String,
    trusted_setup_file: String,
    #[cfg(feature = "gpu")] precomputations: &(
        PlonkSnarkVerifierCircuitDeviceSetupWrapper,
        SnarkWrapperVK,
    ),
    disable_zk: bool,
    supported_protocol_versions: &SupportedProtocolVersions,
) -> anyhow::Result<bool> {
    tracing::debug!("Picking job from sequencer {}", client.sequencer_url());
    let snark_proof_input = match client.pick_snark_job().await {
        Ok(Some(snark_proof_input)) => {
            if snark_proof_input.fri_proofs.is_empty() {
                let err_msg =
                    "No FRI proofs were sent, issue with Prover API/Sequencer, quitting...";
                tracing::error!(err_msg);
                return Err(anyhow::anyhow!(err_msg));
            }
            if !supported_protocol_versions.contains(&snark_proof_input.vk_hash) {
                tracing::error!(
                    "Received unsupported protocol version with vk_hash {} for batches between [{} and {}] from sequencer {}, skipping",
                    snark_proof_input.vk_hash,
                    snark_proof_input.from_batch_number.0,
                    snark_proof_input.to_batch_number.0,
                    client.sequencer_url()
                );
                return Ok(false);
            }
            snark_proof_input
        }
        Ok(None) => {
            tracing::debug!(
                "No SNARK jobs found from sequencer {}",
                client.sequencer_url()
            );
            return Ok(false);
        }
        Err(e) => {
            // Check if the error is a timeout error
            if e.downcast_ref::<reqwest::Error>()
                .map(|err| err.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout waiting for response from sequencer {}: {e:?}",
                    client.sequencer_url()
                );
                tracing::error!("Exiting prover due to timeout");
                SNARK_PROVER_METRICS.timeout_errors.inc();
                return Ok(false);
            }
            tracing::error!(
                "Failed to pick SNARK job from sequencer {}: {e:?}",
                client.sequencer_url()
            );
            return Ok(false);
        }
    };
    let start_batch = snark_proof_input.from_batch_number;
    let end_batch = snark_proof_input.to_batch_number;
    let vk_hash = snark_proof_input.vk_hash.clone();

    tracing::info!(
        "Finished picking job from sequencer {} with VK hash {}, will aggregate from {} to {} inclusive",
        client.sequencer_url(),
        vk_hash,
        start_batch,
        end_batch,
    );
    tracing::info!("Initializing GPU state");
    #[cfg(feature = "gpu")]
    let mut gpu_state_store = GpuSharedState::new(
        verifier_binary,
        zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
    );
    #[cfg(feature = "gpu")]
    let mut gpu_state = Some(&mut gpu_state_store);
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = None;
    tracing::info!("Finished initializing GPU state");

    let mut stats = SnarkProofTimeStats::new();

    let proof = stats.measure_step(SnarkStage::MergeFri, || {
        merge_fris(snark_proof_input, verifier_binary, &mut gpu_state)
    });

    // Drop GPU state to release the airbender GPU resources (as now Final Proof will be taking them).
    #[cfg(feature = "gpu")]
    drop(gpu_state_store);

    tracing::info!("Creating final proof before SNARKification");

    let final_proof = stats.measure_step(SnarkStage::FinalProof, || {
        create_final_proofs_from_program_proof(
            proof,
            RecursionStrategy::UseReducedLog23Machine,
            #[cfg(feature = "gpu")]
            true,
            #[cfg(not(feature = "gpu"))]
            false,
        )
    });

    tracing::info!("Finished creating final proof");
    let one_fri_path = Path::new(&output_dir).join("one_fri.tmp");

    serialize_to_file(&final_proof, &one_fri_path);

    tracing::info!("SNARKifying proof");
    let start = Instant::now();
    // SYSCOIN
    let snark_proof_path = Path::new(&output_dir).join("snark_proof.json");
    // Avoid accidentally reusing an old proof artifact when SNARKification fails.
    if snark_proof_path.exists() {
        std::fs::remove_file(&snark_proof_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to remove stale snark proof artifact at {}: {e}",
                snark_proof_path.display()
            )
        })?;
    }
    let prove_result = {
        let snark_input = one_fri_path.into_os_string().into_string().unwrap();
        let snark_output_dir = output_dir.clone();
        let snark_trusted_setup_file = trusted_setup_file.clone();
        let use_zk = !disable_zk;

        if let Some(stack_size) = configured_snark_thread_stack_size() {
            tracing::info!(
                "Running SNARKification on a dedicated thread with {} bytes of stack",
                stack_size
            );
            std::thread::scope(|scope| {
                let handle = std::thread::Builder::new()
                    .name("snarkify-proof".to_owned())
                    .stack_size(stack_size)
                    .spawn_scoped(scope, || {
                        prove(
                            snark_input,
                            snark_output_dir,
                            Some(snark_trusted_setup_file),
                            false,
                            #[cfg(feature = "gpu")]
                            Some(precomputations),
                            use_zk,
                        )
                        .map_err(|error| error.to_string())
                    })
                    .map_err(|error| {
                        format!("failed to spawn dedicated SNARKification thread: {error}")
                    })?;
                handle.join().map_err(panic_payload_to_string)?
            })
        } else {
            prove(
                snark_input,
                snark_output_dir,
                Some(snark_trusted_setup_file),
                false,
                #[cfg(feature = "gpu")]
                Some(precomputations),
                use_zk,
            )
            .map_err(|error| error.to_string())
        }
    };

    match prove_result {
        Ok(()) => {
            stats.observe_step(SnarkStage::Snark, start.elapsed());

            stats.observe_full();

            tracing::info!("Finished generating proof, time stats: {}", stats);
        }
        Err(error) => {
            tracing::error!("failed to SNARKify proof: {}, time stats: {}", error, stats);
            // Do not submit proof when SNARKification failed.
            return Ok(false);
        }
    }
    // SYSCOIN
    if !snark_proof_path.exists() {
        tracing::error!(
            "SNARKification finished but output proof file is missing at {}",
            snark_proof_path.display()
        );
        return Ok(false);
    }
    // SYSCOIN
    let snark_proof: SnarkWrapperProof = deserialize_from_file(snark_proof_path.to_str().unwrap());

    match client
        .submit_snark_proof(start_batch, end_batch, vk_hash.clone(), snark_proof)
        .await
    {
        Ok(()) => {
            tracing::info!(
                "Successfully submitted SNARK proof for batches {} to {} with vk hash {} to sequencer {}",
                start_batch,
                end_batch,
                vk_hash,
                client.sequencer_url()
            );

            SNARK_PROVER_METRICS
                .latest_proven_batch
                .set(end_batch.0 as i64);

            Ok(true)
        }
        Err(e) => {
            // Check if the error is a timeout error
            if e.downcast_ref::<reqwest::Error>()
                .map(|err| err.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout submitting SNARK proof with vk hash {} for batches {} to {} to sequencer {}: {e:?}",
                    vk_hash,
                    start_batch,
                    end_batch,
                    client.sequencer_url()
                );
                tracing::error!("Exiting prover due to timeout");
                SNARK_PROVER_METRICS.timeout_errors.inc();
            } else {
                tracing::error!(
                    "Failed to submit SNARK job with vk hash {}, batches {} to {} to sequencer {} due to {e:?}, skipping",
                    vk_hash,
                    start_batch,
                    end_batch,
                    client.sequencer_url(),
                );
            }
            // Return false so caller doesn't increment proof counter
            Ok(false)
        }
    }
}

pub fn deserialize_from_file<T: serde::de::DeserializeOwned>(filename: &str) -> T {
    let src = std::fs::File::open(filename).unwrap();
    serde_json::from_reader(src).unwrap()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use url::Url;
    use zksync_sequencer_proof_client::{
        FriJobInputs, L2BatchNumber, QueueJobStatus, SnarkProofInputs,
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
    async fn snark_clients_score_by_head_batch_age_not_oldest_tail() {
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

        let ordered = order_clients_by_oldest_unassigned(&clients, JobQueueStage::Snark).await;

        assert_eq!(ordered, vec![1, 0]);
    }
}
