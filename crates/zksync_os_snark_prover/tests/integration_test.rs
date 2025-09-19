use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
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
    let trusted_setup_file: Option<String> = Some("../../crs/setup_compact.key".to_string());
    let client = FileBasedProofClient::default();
    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    tracing::info!("Starting Zksync OS SNARK prover test");

    let success = run_inner(
        &client,
        &verifier_binary,
        output_dir.clone(),
        trusted_setup_file.clone(),
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
