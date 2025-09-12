#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        time::{Instant, SystemTime},
    };

    use crate::{run_fri_prover, run_snark_prover};
    use zksync_airbender_cli::prover_utils::{load_binary_from_path, GpuSharedState};
    use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
    use zksync_sequencer_proof_client::{utils::FileBasedProofClient, ProofClient};

    #[tokio::test]
    async fn test_e2e_prover_service() {
        // To run the test you need to have the following files:
        // - ../../fri_job.json
        // - ../../snark_job.json

        // Also you need to specify stack size (e.g. 40MB)
        // RUST_MIN_STACK=41943040 cargo test test_e2e_prover_service --release -- --nocapture

        // Arguments:
        let max_snark_latency = 600;
        let max_fris_per_snark = 2;
        let circuit_limit = 10000;
        let iterations = Some(2);
        let fri_path = Some(PathBuf::from("../../outputs/fri_proof.json"));

        let output_dir: String = "../../outputs".to_string();
        let trusted_setup_file: Option<String> = Some("../../crs/setup_compact.key".to_string());

        let client = <FileBasedProofClient as ProofClient>::new("../../".to_string());

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

        println!("Starting Zksync OS Prover Service test");
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
            println!("Running FRI prover");
            loop {
                run_fri_prover(
                    &client,
                    &binary,
                    circuit_limit,
                    &mut gpu_state,
                    fri_path.clone(),
                    &mut fri_proof_count,
                )
                .await
                .unwrap();

                if snark_latency.elapsed().unwrap().as_secs() >= max_snark_latency {
                    println!("SNARK latency reached max_snark_latency ({max_snark_latency} seconds), exiting FRI prover");
                    break;
                } else if fri_proof_count >= max_fris_per_snark {
                    println!("FRI proof count reached max_fris_per_snark ({max_fris_per_snark}), exiting FRI prover");
                    break;
                }
            }

            // Here we do exactly one SNARK proof
            println!("Running SNARK prover");
            run_snark_prover(
                &client,
                output_dir.clone(),
                trusted_setup_file.clone(),
                gpu_state,
                &verifier_binary,
            )
            .await
            .unwrap();

            // Increment SNARK proof counter
            println!("Exiting SNARK prover");
            snark_proof_count += 1;
            snark_latency = SystemTime::now();

            // Check if we've reached the iteration limit
            if let Some(max_iterations) = iterations {
                if snark_proof_count >= max_iterations {
                    println!("Reached maximum iterations ({max_iterations}), exiting...",);
                    break;
                }
            }
        }

        println!("Total e2e proof time: {:?}", proof_time.elapsed());
    }
}
