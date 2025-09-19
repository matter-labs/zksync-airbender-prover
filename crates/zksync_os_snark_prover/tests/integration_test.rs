use std::path::Path;

#[cfg(feature = "gpu")]
use zkos_wrapper::gpu::snark::gpu_create_snark_setup_data;
use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
#[cfg(feature = "gpu")]
use zksync_os_snark_prover::compute_compression_vk;
use zksync_os_snark_prover::{init_tracing, run_inner};
use zksync_sequencer_proof_client::{
    file_based_proof_client::FileBasedProofClient, sequencer_proof_client::SequencerProofClient,
    ProofClient,
};

#[tokio::test]
async fn test_snark_prover() {
    // To run the test you need to have the following files:
    // - ../../test_data/snark_job.json

    // Also you need to specify stack size (e.g. 40MB)
    // RUST_MIN_STACK=41943040 cargo test test_snark_prover --release --features gpu -- --nocapture

    init_tracing();
    let output_dir: String = "../../outputs".to_string();
    let trusted_setup_file: String = "../../crs/setup_compact.key".to_string();
    let client = FileBasedProofClient::default();
    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);
    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };
    let _binary_path = Path::new(&manifest_path)
        .join("../../multiblock_batch.bin")
        .to_str()
        .unwrap()
        .to_string();

    #[cfg(feature = "gpu")]
    let precomputations = {
        tracing::info!("Computing SNARK precomputations");
        let compression_vk = compute_compression_vk(_binary_path);
        let precomputations = gpu_create_snark_setup_data(compression_vk, &trusted_setup_file);
        tracing::info!("Finished computing SNARK precomputations");
        precomputations
    };

    tracing::info!("Starting Zksync OS SNARK prover test");

    let success = run_inner(
        &client,
        &verifier_binary,
        output_dir.clone(),
        trusted_setup_file.clone(),
        #[cfg(feature = "gpu")]
        precomputations.clone(),
    )
    .await
    .expect("Failed to run SNARK prover");
    assert!(success);
}

#[tokio::test]
async fn serialize_snark_job() {
    init_tracing();
    let client = SequencerProofClient::new("http://localhost:3124".to_string());
    let file_based_client = FileBasedProofClient::default();

    let snark_proof_inputs = match client.pick_snark_job().await {
        Err(err) => {
            tracing::error!("Error fetching next snark job: {err}");
            return;
        }
        Ok(Some(snark_proof_inputs)) => snark_proof_inputs,
        Ok(None) => {
            tracing::info!("No pending snark jobs");
            return;
        }
    };

    file_based_client
        .serialize_snark_job(snark_proof_inputs)
        .unwrap();
}
