#[cfg(test)]
mod tests {
    use std::{path::Path, time::SystemTime};

    use crate::create_proof;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use zksync_airbender_cli::prover_utils::{
        load_binary_from_path, GpuSharedState,
    };
    use zksync_sequencer_proof_client::{utils::FileBasedProofClient, ProofClient};

    use super::*;

    #[tokio::test]
    async fn test_fri_prover() {
        // To run the test you need to have the following files:
        // - ../../fri_job.json

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
        // For regular fri proving, we keep using reduced RiscV machine.
        #[cfg(feature = "gpu")]
        let mut gpu_state = GpuSharedState::new(
            &binary,
            zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
        );
        #[cfg(not(feature = "gpu"))]
        let mut gpu_state = GpuSharedState::new(&binary);

        println!("Starting Zksync OS FRI prover test");

        let (block_number, prover_input) = match client.pick_fri_job().await {
            Err(err) => panic!("Error picking fri job: {err}"),
            Ok(Some(next_block)) => next_block,
            Ok(None) => panic!("No pending blocks to prover"),
        };

        // make prover_input (Vec<u8>) into Vec<u32>:
        let prover_input: Vec<u32> = prover_input
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();

        println!(
            "{:?} starting proving block number {}",
            SystemTime::now(),
            block_number
        );

        let proof = create_proof(prover_input, &binary, 10000, &mut gpu_state);

        println!(
            "{:?} finished proving block number {}",
            SystemTime::now(),
            block_number
        );
        let proof_bytes: Vec<u8> =
            bincode::serde::encode_to_vec(&proof, bincode::config::standard())
                .expect("failed to bincode-serialize proof");

        // 2) base64-encode that binary blob
        let proof_b64 = STANDARD.encode(&proof_bytes);

        match client.submit_fri_proof(block_number, proof_b64).await {
            Ok(_) => println!(
                "{:?} successfully submitted proof for block number {}",
                SystemTime::now(),
                block_number
            ),
            Err(err) => {
                eprintln!(
                    "{:?} failed to submit proof for block number {}: {}",
                    SystemTime::now(),
                    block_number,
                    err
                );
            }
        }
    }
}
