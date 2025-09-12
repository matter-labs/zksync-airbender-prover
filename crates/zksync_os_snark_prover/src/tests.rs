#[cfg(test)]
mod tests {
    use std::{path::Path, time::Instant};

    use super::*;
    use crate::{deserialize_from_file, merge_fris};
    use zkos_wrapper::{prove, SnarkWrapperProof};
    use zksync_airbender_cli::prover_utils::{
        create_final_proofs_from_program_proof, serialize_to_file, GpuSharedState,
    };
    use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
    use zksync_sequencer_proof_client::{utils::FileBasedProofClient, ProofClient};

    #[tokio::test]
    async fn test_snark_prover() {
        // To run the test you need to have the following files:
        // - ../../snark_job.json

        // Also you need to specify stack size (e.g. 40MB)
        // RUST_MIN_STACK=41943040 cargo test test_snark_prover --release -- --nocapture

        let output_dir: String = "../../outputs".to_string();
        let trusted_setup_file: Option<String> = Some("../../crs/setup_compact.key".to_string());
        let client = <FileBasedProofClient as ProofClient>::new("../../".to_string());

        let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);
        #[cfg(feature = "gpu")]
        let mut gpu_state = GpuSharedState::new(
            &verifier_binary,
            zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
        );
        #[cfg(not(feature = "gpu"))]
        let mut gpu_state = GpuSharedState::new(&verifier_binary);

        println!("Starting Zksync OS SNARK prover test");
        let proof_time = Instant::now();

        let snark_proof_input = match client.pick_snark_job().await {
            Err(err) => panic!("Error picking snark job: {err}"),
            Ok(Some(snark_proof_input)) => snark_proof_input,
            Ok(None) => panic!("No pending blocks to prover"),
        };

        let start_block = snark_proof_input.from_block_number;
        let end_block = snark_proof_input.to_block_number;
        println!(
            "Finished picking job, will aggregate from {} to {} inclusive",
            start_block, end_block
        );

        let proof = merge_fris(snark_proof_input, &verifier_binary, &mut gpu_state);

        // Drop GPU state to release the airbender GPU resources (as now Final Proof will be taking them).
        #[cfg(feature = "gpu")]
        drop(gpu_state);

        println!("Creating final proof before SNARKification");
        let final_proof = create_final_proofs_from_program_proof(
            proof,
            zksync_airbender_execution_utils::RecursionStrategy::UseReducedLog23Machine,
            // TODO: currently disabled GPU on final proofs, but we should have a switch in the main program
            // that allow people to run in 3 modes:
            // - cpu only
            // - small gpu (then this is false)
            // - gpu (a.k.a large gpu) - then this is true.
            // NOTE: use this as false, if you want to run on a small GPU
            false,
        );

        println!("Finished creating final proof");
        let one_fri_path = Path::new(&output_dir).join("one_fri.tmp");

        serialize_to_file(&final_proof, &one_fri_path);

        println!("SNARKifying proof");
        let snark_time = Instant::now();

        match prove(
            one_fri_path.into_os_string().into_string().unwrap(),
            output_dir.clone(),
            trusted_setup_file.clone(),
            false,
            // TODO: for GPU, we might want to create 'setup' file, and then pass it here for faster running.
            None,
        ) {
            Ok(()) => {
                println!(
                    "SNARKification took {:?}, with total proving time being {:?}",
                    snark_time.elapsed(),
                    proof_time.elapsed()
                );
            }
            Err(e) => {
                println!("failed to SNARKify proof: {e:?}");
            }
        }
        let snark_proof: SnarkWrapperProof = deserialize_from_file(
            Path::new(&output_dir)
                .join("snark_proof.json")
                .to_str()
                .unwrap(),
        );

        match client
            .submit_snark_proof(start_block, end_block, snark_proof)
            .await
        {
            Ok(()) => {
                println!(
                    "Successfully submitted SNARK proof for blocks {} to {}",
                    start_block, end_block
                );
            }
            Err(e) => {
                tracing::error!("Failed to submit SNARK job due to {e:?}, skipping");
            }
        };
    }
}
