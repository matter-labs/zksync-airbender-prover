use std::{path::Path, time::Instant};

use zkos_wrapper::{prove, SnarkWrapperProof};
use zksync_airbender_cli::prover_utils::{
    create_final_proofs_from_program_proof, serialize_to_file, GpuSharedState,
};
use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
use zksync_os_snark_prover::{deserialize_from_file, merge_fris, run_inner};
use zksync_sequencer_proof_client::file_based_proof_client::FileBasedProofClient;

#[tokio::test]
async fn test_snark_prover() {
    // To run the test you need to have the following files:
    // - ../../snark_job.json

    // Also you need to specify stack size (e.g. 40MB)
    // RUST_MIN_STACK=41943040 cargo test test_snark_prover --release -- --nocapture

    let output_dir: String = "../../outputs".to_string();
    let trusted_setup_file: Option<String> = Some("../../crs/setup_compact.key".to_string());
    let client = FileBasedProofClient::new("../../".to_string());

    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);
    #[cfg(feature = "gpu")]
    let mut gpu_state = GpuSharedState::new(
        &verifier_binary,
        zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
    );
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = GpuSharedState::new(&verifier_binary);

    tracing::info!("Starting Zksync OS SNARK prover test");

    let success = run_inner(
        &client,
        &verifier_binary,
        &mut gpu_state,
        output_dir.clone(),
        trusted_setup_file.clone(),
    )
    .await
    .expect("Failed to run SNARK prover");
    assert!(success);
}
