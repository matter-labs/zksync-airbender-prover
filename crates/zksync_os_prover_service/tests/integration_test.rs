use std::{
    path::{Path, PathBuf},
    time::{Instant, SystemTime},
};

use zksync_airbender_cli::prover_utils::{load_binary_from_path, GpuSharedState};
use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
// use zksync_os_prover_service::{run_fri_prover, run_snark_prover};
use zksync_sequencer_proof_client::file_based_proof_client::FileBasedProofClient;

#[tokio::test]
async fn test_e2e_prover_service() {
    // To run the test you need to have the following files:
    // - ../../fri_job.json
    // - ../../snark_job.json

    // Also you need to specify stack size (e.g. 40MB)
    // RUST_MIN_STACK=41943040 cargo test test_e2e_prover_service --release -- --nocapture

    // Arguments:
    let max_snark_latency = Some(600);
    let max_fris_per_snark = Some(2);
    let circuit_limit = 10000;
    let iterations = Some(2);
    let fri_path = Some(PathBuf::from("../../outputs/fri_proof.json"));

    let output_dir: String = "../../outputs".to_string();
    let trusted_setup_file: Option<String> = Some("../../crs/setup_compact.key".to_string());

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
    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    tracing::info!("Starting Zksync OS Prover Service test");
    let proof_time = Instant::now();

    let mut snark_proof_count = 0;
    let mut snark_latency = SystemTime::now();

    loop {
        let mut fri_proof_count = 0;

        // For regular fri proving, we keep using reduced RiscV machine.
        #[cfg(feature = "gpu")]
        let mut gpu_state = GpuSharedState::new(
            &binary,
            zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
        );
        #[cfg(not(feature = "gpu"))]
        let mut gpu_state = GpuSharedState::new(&binary);

        // Run FRI prover until we hit one of the limits
        tracing::info!("Running FRI prover");
        loop {
            let success = zksync_os_fri_prover::run_inner(
                &client,
                &binary,
                circuit_limit,
                &mut gpu_state,
                fri_path.clone(),
            )
            .await
            .expect("Failed to run FRI prover");

            if success {
                fri_proof_count += 1;
            }

            if let Some(max_snark_latency) = max_snark_latency {
                if snark_latency.elapsed().unwrap().as_secs() >= max_snark_latency {
                    tracing::info!("SNARK latency reached max_snark_latency ({max_snark_latency} seconds), exiting FRI prover");
                    break;
                }
            }
            if let Some(max_fris_per_snark) = max_fris_per_snark {
                if fri_proof_count >= max_fris_per_snark {
                    tracing::info!("FRI proof count reached max_fris_per_snark ({max_fris_per_snark}), exiting FRI prover");
                    break;
                }
            }
        }

        // Here we do exactly one SNARK proof
        tracing::info!("Running SNARK prover");
        loop {
            let success = zksync_os_snark_prover::run_inner(
                &client,
                &verifier_binary,
                &mut gpu_state,
                output_dir.clone(),
                trusted_setup_file.clone(),
            )
            .await
            .expect("Failed to run SNARK prover");

            if success {
                // Increment SNARK proof counter
                tracing::info!("Successfully run SNARK prover");
                snark_proof_count += 1;
                snark_latency = SystemTime::now();
                break;
            }
        }

        // Check if we've reached the iteration limit
        if let Some(max_iterations) = iterations {
            if snark_proof_count >= max_iterations {
                tracing::info!("Reached maximum iterations ({max_iterations}), exiting...",);
                break;
            }
        }
    }

    tracing::info!("Total e2e proof time: {:?}", proof_time.elapsed());
}
