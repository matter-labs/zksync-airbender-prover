use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use zksync_airbender_cli::prover_utils::{load_binary_from_path, GpuSharedState};
use zksync_airbender_execution_utils::ProgramProof;
use zksync_sequencer_proof_client::{
    file_based_proof_client::FileBasedProofClient, sequencer_proof_client::SequencerProofClient,
    FailedFriProofPayload, PeekableProofClient, ProofClient,
};

pub async fn peek_fri_job_and_save(
    server_url: &str,
    block_number: u32,
    output_dir: &std::path::Path,
) -> Result<()> {
    tracing::info!("Peeking FRI job for block {}", block_number);

    let sequencer_client = SequencerProofClient::new(server_url.to_string());
    let file_client = FileBasedProofClient::new(output_dir.to_str().unwrap().to_string());

    // Peek job from server
    let (block_num, prover_input) = sequencer_client
        .peek_fri_job(block_number)
        .await?
        .ok_or_else(|| anyhow!("No FRI job found for block {block_number}"))?;

    // Save to file
    file_client.serialize_fri_job(block_num, &prover_input)?;

    tracing::info!(
        "Saved FRI job for block {block_num} to {output_path}",
        output_path = output_dir.join("fri_job.json").display()
    );

    Ok(())
}

pub async fn prove_fri_job_from_peek(
    server_url: &str,
    block_number: u32,
    app_bin_path: &std::path::Path,
    circuit_limit: usize,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    tracing::info!("Starting prove-from-peek for block {block_number}");

    let sequencer_client = SequencerProofClient::new(server_url.to_string());

    // Peek job from server
    tracing::info!("Fetching FRI job from server...");
    let (block_num, prover_input_bytes) = sequencer_client
        .peek_fri_job(block_number)
        .await?
        .ok_or_else(|| anyhow!("No FRI job found for block {block_number}"))?;

    tracing::info!("Successfully fetched job for block {block_num}");

    let prover_input = bytes_to_u32_vec(&prover_input_bytes);
    tracing::info!("Prover input size: {:?} u32 values", prover_input.len());

    // Create proof
    let proof = prove_fri_job_from_input(prover_input, app_bin_path, circuit_limit)?;

    // Save proof if requested
    if let Some(output_path) = output_path {
        save_fri_proof(&proof, output_path)?;
    }

    // Try to verify with failed proof data
    let failed_fri_proof = sequencer_client.get_failed_fri_proof(block_number).await?;
    if let Some(failed_fri_proof) = failed_fri_proof {
        verify_fri_proof_with_failed_proof(failed_fri_proof, proof)?;
    }

    Ok(())
}

pub async fn prove_fri_job_from_file(
    block_number: u32,
    input_dir: &std::path::Path,
    app_bin_path: &std::path::Path,
    circuit_limit: usize,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    tracing::info!("Starting prove-from-file for block {block_number}");

    let file_based_proof_client =
        FileBasedProofClient::new(input_dir.to_str().unwrap().to_string());

    // Load job from file
    tracing::info!("Loading FRI job from file...");
    let (block_num, prover_input_bytes) = file_based_proof_client
        .pick_fri_job()
        .await?
        .ok_or_else(|| {
            anyhow!("No FRI job file found for block {block_number} in {input_dir:?}")
        })?;

    tracing::info!("Successfully loaded job for block {block_num}");

    let prover_input = bytes_to_u32_vec(&prover_input_bytes);
    tracing::info!("Prover input size: {:?} u32 values", prover_input.len());

    // Create proof
    let proof = prove_fri_job_from_input(prover_input, app_bin_path, circuit_limit)?;

    // Save proof if requested
    if let Some(output_path) = output_path {
        save_fri_proof(&proof, output_path)?;
    }

    // Try to verify with failed proof data
    let failed_fri_proof = file_based_proof_client.deserialize_failed_fri_proof()?;
    verify_fri_proof_with_failed_proof(failed_fri_proof, proof)?;

    Ok(())
}

/// Convert prover input bytes to Vec<u32> (little-endian)
fn bytes_to_u32_vec(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

fn prove_fri_job_from_input(
    prover_input: Vec<u32>,
    app_bin_path: &std::path::Path,
    circuit_limit: usize,
) -> Result<ProgramProof> {
    // Load binary
    tracing::info!("Loading binary from: {}", app_bin_path.display());
    let binary = load_binary_from_path(&app_bin_path.to_str().unwrap().to_string());
    tracing::info!("Binary loaded successfully");

    // Create proof
    tracing::info!("Creating proof");

    #[cfg(feature = "gpu")]
    let mut gpu_state = GpuSharedState::new(
        &binary,
        zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
    );
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = GpuSharedState::new(&binary);

    let proof =
        zksync_os_fri_prover::create_proof(prover_input, &binary, circuit_limit, &mut gpu_state);

    tracing::info!("Proof created successfully!");

    Ok(proof)
}

fn save_fri_proof(proof: &ProgramProof, output_path: &std::path::Path) -> Result<()> {
    let proof_bytes: Vec<u8> = bincode::serde::encode_to_vec(proof, bincode::config::standard())
        .expect("failed to bincode-serialize proof");
    let proof_b64 = STANDARD.encode(&proof_bytes);

    std::fs::write(output_path, proof_b64)?;
    tracing::info!("Proof saved to: {}", output_path.display());

    Ok(())
}

fn verify_fri_proof_with_failed_proof(
    failed_fri_proof: FailedFriProofPayload,
    proof: ProgramProof,
) -> Result<()> {
    tracing::info!(
        "Attempting to verify proof with failed proof data: {}",
        failed_fri_proof.batch_number
    );

    let expected_hash_u32s = failed_fri_proof.expected_hash_u32s;
    let failed_proof_final_register_values = failed_fri_proof.proof_final_register_values;
    let proof_bytes = bincode::serde::encode_to_vec(proof, bincode::config::standard())?;
    let failed_proof_bytes = STANDARD.decode(failed_fri_proof.proof)?;

    // TODO: We can include full_statement_verifier later to verify the proof
    if proof_bytes == failed_proof_bytes {
        tracing::info!("Proof verification PASSED");
    } else {
        tracing::warn!("Proof verification FAILED");
        tracing::warn!("Expected: {:?}", expected_hash_u32s);
        tracing::warn!(
            "Failed proof final register values: {:?}",
            failed_proof_final_register_values
        );
    }

    Ok(())
}
