use std::path::Path;

use zksync_airbender_cli::prover_utils::{load_binary_from_path, GpuSharedState};
use zksync_os_fri_prover::run_inner;
use zksync_sequencer_proof_client::file_based_proof_client::FileBasedProofClient;

#[tokio::test]
async fn test_fri_prover() {
    // To run the test you need to have the following files:
    // - ../../fri_job.json

    let client = FileBasedProofClient::new("../../".to_string());

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

    tracing::info!("Starting Zksync OS FRI prover test");

    let success = run_inner(&client, &binary, 10000, &mut gpu_state, None)
        .await
        .expect("Failed to run FRI prover");
    assert!(success);
}
