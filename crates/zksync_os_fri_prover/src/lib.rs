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
use zksync_sequencer_proof_client::SequencerProofClient;

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// Base URL for the proof-data server (e.g., "http://<IP>:<PORT>")
    #[arg(short, long, default_value = "http://localhost:3124")]
    pub base_url: String,
    /// Enable logging and use the logging-enabled binary
    #[arg(long)]
    pub enabled_logging: bool,
    /// Path to `app.bin`
    #[arg(long)]
    pub app_bin_path: Option<PathBuf>,
    /// Circuit limit - max number of MainVM circuits to instantiate to run the block fully
    #[arg(long, default_value = "10000")]
    pub circuit_limit: usize,
    /// Path to the output file
    #[arg(short, long)]
    pub path: Option<PathBuf>,
}

fn create_proof(
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
    println!(
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

    println!(
        "Starting Zksync OS FRI prover for {}",
        client.sequencer_url()
    );

    loop {
        let (block_number, prover_input) = match client.pick_fri_job().await {
            Err(err) => {
                eprintln!("Error fetching next prover job: {err}");
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                continue;
            }
            Ok(Some(next_block)) => next_block,
            Ok(None) => {
                println!("No pending blocks to prove, retrying in 100ms...");
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
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

        let proof = create_proof(prover_input, &binary, args.circuit_limit, &mut gpu_state);
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

        if let Some(ref path) = args.path {
            serialize_to_file(&proof_b64, path);
        }

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
