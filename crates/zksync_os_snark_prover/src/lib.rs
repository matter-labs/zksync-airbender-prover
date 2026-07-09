use protocol_version::SupportedProtocolVersions;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use zkos_wrapper::{
    CompressionProof, SnarkWrapper, SnarkWrapperConfig, SnarkWrapperProof, SnarkWrapperVK,
};
use zksync_airbender_execution_utils::unrolled::UnrolledProgramProof;
use zksync_sequencer_proof_client::{ProofClient, SnarkProofInputs};

use crate::metrics::{SnarkProofTimeStats, SnarkStage, SNARK_PROVER_METRICS};

pub mod metrics;

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

/// Build the SNARK wrapper session used for proving and VK generation.
///
/// The wrapper is constructed without an explicit binary: the verification keys bind the
/// wrapper chain over zkos-wrapper's embedded unified recursion verifier binary, and the
/// app binary is bound through the recursion chain carried inside the FRI proof itself.
pub fn create_snark_wrapper(trusted_setup_file: String) -> anyhow::Result<SnarkWrapper> {
    #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
    let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
        trusted_setup: Some(trusted_setup_file.into()),
        ..Default::default()
    })?;

    // Mirror the old eager GPU precomputation: derive the full VK/setup chain up front so
    // that setup problems surface at startup rather than on the first picked job (and the
    // startup-time metric keeps its meaning). Skipped on CPU, as before.
    #[cfg(feature = "gpu")]
    {
        tracing::info!("Computing SNARK precomputations");
        wrapper.snark_vk()?;
        tracing::info!("Finished computing SNARK precomputations");
    }

    Ok(wrapper)
}

pub fn generate_verification_key(
    // Deprecated: the VK no longer depends on the app binary (see `create_snark_wrapper`).
    _binary_path: String,
    output_dir: String,
    trusted_setup_file: String,
    vk_verification_key_file: Option<String>,
) {
    let result = (|| -> anyhow::Result<()> {
        zkos_wrapper::interface::cmd_generate_vk(
            output_dir.clone().into(),
            None,
            None,
            Some(trusted_setup_file.into()),
            None,
        )?;

        if let Some(vk_file) = vk_verification_key_file {
            let snark_vk_path = Path::new(&output_dir).join("snark_vk.json");
            let vk: SnarkWrapperVK = zkos_wrapper::deserialize_from_file(
                snark_vk_path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF8 output dir {output_dir:?}"))?,
            )?;
            let vk_hash = zkos_wrapper::calculate_verification_key_hash(vk);
            std::fs::write(vk_file, format!("{vk_hash:?}"))?;
        }
        Ok(())
    })();

    match result {
        Ok(()) => tracing::info!("Verification keys generated successfully"),
        Err(e) => tracing::error!("Error generating keys: {e:?}"),
    }
}

pub fn merge_fris(snark_proof_input: SnarkProofInputs) -> anyhow::Result<UnrolledProgramProof> {
    SNARK_PROVER_METRICS
        .fri_proofs_merged
        .set(snark_proof_input.fri_proofs.len() as i64);

    let SnarkProofInputs {
        from_batch_number,
        to_batch_number,
        mut fri_proofs,
        ..
    } = snark_proof_input;

    match fri_proofs.len() {
        1 => {
            tracing::info!("No proof merging needed, only one proof provided");
            Ok(fri_proofs.pop().unwrap())
        }
        // TODO: airbender's unrolled prover stack has no cross-batch proof merging yet
        // (the old universal-verifier `CombinedRecursionLayers` flow was removed).
        // Until it does, the sequencer must schedule exactly one batch per SNARK.
        n => anyhow::bail!(
            "SNARK job for batches {from_batch_number} to {to_batch_number} contains {n} FRI \
             proofs; merging multiple FRI proofs is not supported by the unrolled prover stack \
             yet — configure the sequencer to schedule one batch per SNARK"
        ),
    }
}

pub async fn run_linking_fri_snark(
    // Deprecated: the SNARK wrapper no longer depends on the app binary (see `create_snark_wrapper`).
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

    let mut snark_wrapper = create_snark_wrapper(trusted_setup_file)?;

    SNARK_PROVER_METRICS
        .time_taken_startup
        .observe(startup_started_at.elapsed().as_secs_f64());

    let mut proof_count = 0;

    // Cycle through clients in round-robin fashion
    for client in clients.iter().cycle() {
        tracing::debug!("Polling sequencer: {}", client.sequencer_url());

        let proof_generated = run_inner(
            client.as_ref(),
            &mut snark_wrapper,
            output_dir.clone(),
            disable_zk,
            &supported_versions,
        )
        .await
        .expect("Failed to run SNARK prover");

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
            // If no task was found, wait before trying again
            tracing::info!("No pending SNARK jobs from sequencer, retrying in 5s...");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    Ok(())
}

pub async fn run_inner(
    client: &dyn ProofClient,
    snark_wrapper: &mut SnarkWrapper,
    output_dir: String,
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

    let mut stats = SnarkProofTimeStats::new();

    // A multi-proof job would be re-picked forever, so treat it as a fatal
    // configuration error rather than skipping it.
    let proof = stats.measure_step(SnarkStage::MergeFri, || merge_fris(snark_proof_input))?;

    tracing::info!("Wrapping and compressing FRI proof");

    // Proving failures are fatal: silently skipping would re-pick the same job forever, and a
    // failed attempt can leave the wrapper's cached GPU state unusable for the FRI phase of the
    // zksync_os_prover_service service that runs FRI and SNARK on the same process.
    let stage_start = Instant::now();
    let compression_proof: CompressionProof = (|| {
        let risc_wrapper_proof = snark_wrapper.prove_risc_wrapper(proof)?;
        snark_wrapper.prove_compression(risc_wrapper_proof)
    })()
    .map_err(|e| anyhow::anyhow!("failed to wrap/compress FRI proof: {e:?}"))?;
    stats.observe_step(SnarkStage::FinalProof, stage_start.elapsed());

    tracing::info!("SNARKifying proof");
    // note that the API is use_zk, so we invert the disable_zk flag
    let stage_start = Instant::now();
    let snark_proof: SnarkWrapperProof = snark_wrapper
        .prove_snark(compression_proof, !disable_zk)
        .map_err(|e| anyhow::anyhow!("failed to SNARKify proof: {e:?}"))?;
    stats.observe_step(SnarkStage::Snark, stage_start.elapsed());
    stats.observe_full();
    tracing::info!("Finished generating proof, time stats: {}", stats);

    // Persist the proof next to the other artifacts, mirroring the old flow (best effort).
    let snark_proof_path = Path::new(&output_dir).join("snark_proof.json");
    if let Some(path) = snark_proof_path.to_str() {
        if let Err(e) = zkos_wrapper::serialize_to_file(&snark_proof, path) {
            tracing::warn!("failed to persist SNARK proof to {path}: {e:?}");
        }
    }

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
