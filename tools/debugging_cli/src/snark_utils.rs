use anyhow::{anyhow, Result};
#[cfg(feature = "gpu")]
use proof_compression::serialization::PlonkSnarkVerifierCircuitDeviceSetupWrapper;
use std::path::Path;
#[cfg(feature = "gpu")]
use zkos_wrapper::{
    generate_risk_wrapper_vk,
    gpu::{compression::get_compression_setup, snark::gpu_create_snark_setup_data},
    BoojumWorker, CompressionVK, SnarkWrapperVK,
};
use zkos_wrapper::{prove, serialize_to_file, SnarkWrapperProof};
use zksync_airbender_cli::prover_utils::{create_final_proofs_from_program_proof, GpuSharedState};
use zksync_airbender_execution_utils::{
    get_padded_binary, RecursionStrategy, UNIVERSAL_CIRCUIT_VERIFIER,
};
#[cfg(feature = "gpu")]
use zksync_os_snark_prover::compute_compression_vk;
use zksync_os_snark_prover::merge_fris;
use zksync_sequencer_proof_client::{
    file_based_proof_client::FileBasedProofClient, sequencer_proof_client::SequencerProofClient,
    PeekableProofClient, ProofClient, SnarkProofInputs,
};

// Determine input and output for each stage
pub const MERGED_FRI_FILE: &str = "merged_fri.json";
pub const FINAL_PROOF_FILE: &str = "final_proof.json";
pub const SNARK_PROOF_FILE: &str = "snark_proof.json";

/// Represents which stages to run in the SNARK proving process
#[derive(Debug, Clone)]
pub struct SnarkStages {
    pub merge_fris: bool,
    pub final_proof: bool,
    pub snarkifying: bool,
}

/// Peek a SNARK job from server and save it to file
pub async fn peek_snark_job_and_save(
    server_url: &str,
    from_block_number: u32,
    to_block_number: u32,
    output_dir: &Path,
) -> Result<()> {
    tracing::info!(
        "Peeking SNARK job for blocks {} to {}",
        from_block_number,
        to_block_number
    );

    let sequencer_client = SequencerProofClient::new(server_url.to_string());
    let file_client = FileBasedProofClient::new(output_dir.to_str().unwrap().to_string());

    // Peek job from server
    let snark_proof_inputs = sequencer_client
        .peek_snark_job(from_block_number, to_block_number)
        .await?
        .ok_or_else(|| {
            anyhow!("No SNARK job found for blocks {from_block_number} to {to_block_number}")
        })?;

    // Save to file
    file_client.serialize_snark_job(&snark_proof_inputs)?;

    tracing::info!(
        "Saved SNARK job for blocks {} to {} to {}",
        from_block_number,
        to_block_number,
        output_dir.join("snark_job.json").display()
    );

    Ok(())
}

/// Prove a SNARK job fetched via peek endpoint
pub async fn prove_snark_job_from_peek(
    server_url: &str,
    from_block_number: u32,
    to_block_number: u32,
    trusted_setup_file: &Path,
    output_dir: &Path,
    stages: SnarkStages,
) -> Result<()> {
    tracing::info!(
        "Starting SNARK prove-from-peek for blocks {} to {}",
        from_block_number,
        to_block_number
    );

    let sequencer_client = SequencerProofClient::new(server_url.to_string());

    // Peek job from server
    tracing::info!("Fetching SNARK job from server...");
    let snark_proof_inputs = sequencer_client
        .peek_snark_job(from_block_number, to_block_number)
        .await?
        .ok_or_else(|| {
            anyhow!("No SNARK job found for blocks {from_block_number} to {to_block_number}")
        })?;

    tracing::info!(
        "Successfully fetched SNARK job with {} FRI proofs",
        snark_proof_inputs.fri_proofs.len()
    );

    // Create proof with specified stages
    prove_snark_job_internal(snark_proof_inputs, trusted_setup_file, output_dir, stages).await?;

    Ok(())
}

/// Prove a SNARK job loaded from file
pub async fn prove_snark_job_from_file(
    input_dir: &Path,
    trusted_setup_file: &Path,
    output_dir: &Path,
    stages: SnarkStages,
) -> Result<()> {
    tracing::info!("Starting SNARK prove-from-file");

    let file_client = FileBasedProofClient::new(input_dir.to_str().unwrap().to_string());

    // Load job from file
    tracing::info!("Loading SNARK job from file...");
    let snark_proof_inputs = file_client
        .pick_snark_job()
        .await?
        .ok_or_else(|| anyhow!("No SNARK job file found in {input_dir:?}"))?;

    tracing::info!(
        "Successfully loaded SNARK job with {} FRI proofs",
        snark_proof_inputs.fri_proofs.len()
    );

    // Create proof with specified stages
    prove_snark_job_internal(snark_proof_inputs, trusted_setup_file, output_dir, stages).await?;

    Ok(())
}

/// Internal function to run the SNARK proving stages
async fn prove_snark_job_internal(
    snark_proof_inputs: SnarkProofInputs,
    trusted_setup_file: &Path,
    output_dir: &Path,
    stages: SnarkStages,
) -> Result<()> {
    // Validate that at least one stage is enabled
    if !stages.merge_fris && !stages.final_proof && !stages.snarkifying {
        return Err(anyhow!("At least one stage must be enabled"));
    }

    // Determine input and output for each stage (all in output_dir)
    let merged_fri_path = output_dir.join(MERGED_FRI_FILE);
    let final_proof_path = output_dir.join(FINAL_PROOF_FILE);
    let snark_proof_path = output_dir.join(SNARK_PROOF_FILE);

    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    // Stage 1: Merge FRIs
    let program_proof = if stages.merge_fris {
        tracing::info!("=== Stage 1: Merging FRI proofs ===");

        #[cfg(feature = "gpu")]
        let mut gpu_state = GpuSharedState::new(
            &verifier_binary,
            zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
        );
        #[cfg(not(feature = "gpu"))]
        let mut gpu_state = GpuSharedState::new(&verifier_binary);

        let merged_proof = merge_fris(snark_proof_inputs, &verifier_binary, &mut gpu_state);

        // Save merged proof to output_dir
        serialize_to_file(&merged_proof, &merged_fri_path);
        tracing::info!("Merged FRI proof saved to: {}", merged_fri_path.display());

        // Drop GPU state to release resources
        #[cfg(feature = "gpu")]
        drop(gpu_state);

        merged_proof
    } else {
        // Load from file if skipping merge_fris
        tracing::info!("Skipping merge_fris stage, loading from file...");
        deserialize_from_file(&merged_fri_path)
            .map_err(|e| anyhow!("Failed to load merged FRI proof: {e}"))?
    };

    // Stage 2: Final proof
    if stages.final_proof {
        tracing::info!("=== Stage 2: Creating final proof ===");

        let final_proof = create_final_proofs_from_program_proof(
            program_proof,
            RecursionStrategy::UseReducedLog23Machine,
            true, // GPU enabled
        );

        // Save final proof to output_dir
        serialize_to_file(&final_proof, &final_proof_path);
        tracing::info!("Final proof saved to: {}", final_proof_path.display());
    } else if stages.snarkifying {
        // If skipping final_proof but running snarkifying, verify file exists
        tracing::info!("Skipping final_proof stage, will use existing file for SNARKification");
        if !final_proof_path.exists() {
            return Err(anyhow!(
                "Final proof file not found at {}, cannot run snarkifying stage",
                final_proof_path.display()
            ));
        }
    }

    // Stage 3: SNARKification
    if stages.snarkifying {
        tracing::info!("=== Stage 3: SNARKifying proof ===");

        // Use existing final_proof.bin file directly (no temporary copy needed)
        tracing::info!("Using final proof from: {}", final_proof_path.display());

        #[cfg(feature = "gpu")]
        let precomputations = {
            tracing::info!("Computing SNARK precomputations");
            let compression_vk = compute_compression_vk(_binary_path);
            let precomputations = gpu_create_snark_setup_data(compression_vk, &trusted_setup_file);
            tracing::info!("Finished computing SNARK precomputations");
            precomputations
        };

        prove(
            final_proof_path.to_str().unwrap().to_string(),
            output_dir.to_str().unwrap().to_string(),
            Some(trusted_setup_file.to_str().unwrap().to_string()),
            false,
            #[cfg(feature = "gpu")]
            precomputations,
        )
        .map_err(|e| anyhow!("SNARKification failed: {e}"))?;

        tracing::info!("SNARK proof saved to: {}", snark_proof_path.display());

        // Verify the SNARK proof was created
        let _snark_proof: SnarkWrapperProof = deserialize_from_file(&snark_proof_path)?;
        tracing::info!("Successfully verified SNARK proof file");
    }

    tracing::info!("=== All requested stages completed successfully ===");
    Ok(())
}

fn deserialize_from_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file =
        std::fs::File::open(path).map_err(|e| anyhow!("Failed to open file {path:?}: {e}"))?;
    let result: T = serde_json::from_reader(file)
        .map_err(|e| anyhow!("Failed to deserialize from {path:?}: {e}"))?;
    Ok(result)
}
