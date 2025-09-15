use std::{
    path::{Path, PathBuf},
    time::SystemTime,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use clap::Parser;
use zksync_airbender_cli::prover_utils::{
    create_proofs_internal, create_recursion_proofs, load_binary_from_path, serialize_to_file,
    GpuSharedState,
};
use zksync_airbender_execution_utils::{Machine, ProgramProof, RecursionStrategy};
use zksync_sequencer_proof_client::{sequencer_proof_client::SequencerProofClient, ProofClient};

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

pub fn create_proof(
    prover_input: Vec<u32>,
    binary: &Vec<u32>,
    circuit_limit: usize,
    _gpu_state: &mut GpuSharedState,
) -> ProgramProof {
    let mut timing = Some(0f64);
    let (proof_list, proof_metadata) = create_proofs_internal(
        binary,
        prover_input,
        &Machine::Standard,
        circuit_limit,
        None,
        #[cfg(feature = "gpu")]
        &mut Some(_gpu_state),
        #[cfg(not(feature = "gpu"))]
        &mut None,
        &mut timing, // timing info
    );
    let (recursion_proof_list, recursion_proof_metadata) = create_recursion_proofs(
        proof_list,
        proof_metadata,
        // This is the default strategy (where recursion is done on reduced machine, and final step on 23 machine).
        RecursionStrategy::UseReducedLog23Machine,
        &None,
        #[cfg(feature = "gpu")]
        &mut Some(_gpu_state),
        #[cfg(not(feature = "gpu"))]
        &mut None,
        &mut timing, // timing info
    );

    ProgramProof::from_proof_list_and_metadata(&recursion_proof_list, &recursion_proof_metadata)
}

pub async fn run(args: Args) {
    init_tracing();
    tracing::info!(
        "running without logging, disregarding enabled_logging flag = {}",
        args.enabled_logging
    );

    let client = SequencerProofClient::new(args.base_url);

    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };
    let binary_path = args
        .app_bin_path
        .unwrap_or_else(|| Path::new(&manifest_path).join("../../multiblock_batch.bin"));
    let binary = load_binary_from_path(&binary_path.to_str().unwrap().to_string());
    // For regular fri proving, we keep using reduced RiscV machine.
    #[cfg(feature = "gpu")]
    let mut gpu_state = GpuSharedState::new(
        &binary,
        zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
    );
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = GpuSharedState::new(&binary);

    tracing::info!(
        "Starting Zksync OS FRI prover for {}",
        client.sequencer_url()
    );

    let mut proof_count = 0;

    loop {
        let success = run_inner(
            &client,
            &binary,
            args.circuit_limit,
            &mut gpu_state,
            args.path.clone(),
        )
        .await
        .expect("Failed to run FRI prover");

        if success {
            proof_count += 1;
        }

        // Check if we've reached the iteration limit
        if let Some(max_iterations) = args.iterations {
            if proof_count >= max_iterations {
                tracing::info!("Reached maximum iterations ({max_iterations}), exiting...",);
                break;
            }
        }
    }
}

pub async fn run_inner<P: ProofClient>(
    client: &P,
    binary: &Vec<u32>,
    circuit_limit: usize,
    gpu_state: &mut GpuSharedState,
    path: Option<PathBuf>,
) -> anyhow::Result<bool> {
    let (block_number, prover_input) = match client.pick_fri_job().await {
        Err(err) => {
            tracing::error!("Error fetching next prover job: {err}");
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            return Ok(false);
        }
        Ok(Some(next_block)) => next_block,
        Ok(None) => {
            tracing::info!("No pending blocks to prove, retrying in 100ms...");
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            return Ok(false);
        }
    };

    // make prover_input (Vec<u8>) into Vec<u32>:
    let prover_input: Vec<u32> = prover_input
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();

    tracing::info!(
        "{:?} starting proving block number {}",
        SystemTime::now(),
        block_number
    );

    let proof = create_proof(prover_input, &binary, circuit_limit, gpu_state);

    tracing::info!(
        "{:?} finished proving block number {}",
        SystemTime::now(),
        block_number
    );
    let proof_bytes: Vec<u8> = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .expect("failed to bincode-serialize proof");

    // 2) base64-encode that binary blob
    let proof_b64 = STANDARD.encode(&proof_bytes);

    if let Some(ref path) = path {
        serialize_to_file(&proof_b64, path);
    }

    match client.submit_fri_proof(block_number, proof_b64).await {
        Ok(_) => tracing::info!(
            "{:?} successfully submitted proof for block number {}",
            SystemTime::now(),
            block_number
        ),
        Err(err) => {
            tracing::error!(
                "{:?} failed to submit proof for block number {}: {}",
                SystemTime::now(),
                block_number,
                err
            );
        }
    }

    Ok(true)
}
