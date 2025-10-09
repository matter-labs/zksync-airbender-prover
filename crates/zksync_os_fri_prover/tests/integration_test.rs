use std::path::{Path, PathBuf};

use anyhow::Context;
use zksync_airbender_cli::prover_utils::{load_binary_from_path, GpuSharedState};
use zksync_os_fri_prover::{init_tracing, run_inner};
use zksync_sequencer_proof_client::{
    file_based_proof_client::FileBasedProofClient, sequencer_proof_client::SequencerProofClient,
    ProofClient,
};

#[tokio::test]
async fn test_fri_prover() {
    // To run the test you need to have the following files:
    // - ../../test_data/fri_job.json

    init_tracing();
    let client = FileBasedProofClient::default();

    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };
    let binary_path = Path::new(&manifest_path)
        .join("../../multiblock_batch.bin")
        .to_str()
        .unwrap()
        .to_string();
    let binary = load_binary_from_path(&binary_path);
    // For regular fri proving, we keep using reduced RiscV machine.
    #[cfg(feature = "gpu")]
    let mut gpu_state = GpuSharedState::new(
        &binary,
        zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
    );
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = GpuSharedState::new(&binary);

    let path = Some(PathBuf::from("../../test_data/fri_proof.json"));

    tracing::info!("Starting Zksync OS FRI prover test");

    let success = run_inner(&client, &binary, 10000, &mut gpu_state, path)
        .await
        .expect("Failed to run FRI prover");
    assert!(success);
}

#[tokio::test]
async fn test_peek_fri_job_to_file() {
    init_tracing();
    let client = SequencerProofClient::new("https://zksync-os-stage-rollup-leader.zksync.dev/".to_string());
    let file_based_client = FileBasedProofClient::new("../../peek_from_stage_rollup/".to_string());
    let block_number = 663;
    peek_fri_job_to_file(&client, &file_based_client, block_number).await.expect("Failed to peek fri job to file");
}

#[tokio::test]
async fn test_pick_fri_job_to_file() {
    init_tracing();
    let client = SequencerProofClient::new("https://zksync-os-stage-rollup-leader.zksync.dev/".to_string());
    let file_based_client = FileBasedProofClient::new("../../pick_from_stage_rollup/".to_string());
    
    let (block_number, prover_input) = match client.pick_fri_job().await {
        Err(err) => {
            tracing::error!("Error fetching next prover job: {err}");
            return;
        }
        Ok(Some(next_block)) => next_block,
        Ok(None) => {
            tracing::info!("No pending blocks to prove");
            return;
        }
    };

    file_based_client
        .serialize_fri_job(block_number, prover_input)
        .context(format!(
            "Failed to serialize fri job for block {block_number}"
        )).expect("Failed to serialize fri job to file");

    tracing::info!("Picked FRI job for block {block_number}");
}

pub async fn peek_fri_job_to_file(
    client: &SequencerProofClient,
    file_based_client: &FileBasedProofClient,
    block_number: u32,
) -> anyhow::Result<()> {
    let (block_number, prover_input) = match client.peek_fri_job(block_number).await {
        Err(err) => {
            tracing::error!("Error fetching next prover job: {err}");
            return Err(err);
        }
        Ok(Some(next_block)) => next_block,
        Ok(None) => {
            tracing::info!("No pending blocks to prove");
            return Ok(());
        }
    };

    file_based_client
        .serialize_fri_job(block_number, prover_input)
        .context(format!(
            "Failed to serialize fri job for block {block_number}"
        ))?;
    Ok(())
}
