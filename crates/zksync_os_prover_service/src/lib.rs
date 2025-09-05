pub mod utils;

use std::{
    path::{Path, PathBuf},
    time::{Instant, SystemTime},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand, ValueEnum};
use zkos_wrapper::{prove, SnarkWrapperProof};
#[cfg(feature = "gpu")]
use zksync_airbender_cli::prover_utils::GpuSharedState;
use zksync_airbender_cli::prover_utils::{create_final_proofs_from_program_proof, load_binary_from_path, serialize_to_file};
use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
use zksync_os_fri_prover::create_proof;
use zksync_sequencer_proof_client::SequencerProofClient;

#[derive(Debug, Clone, ValueEnum)]
pub enum GPUMode {
    /// Run everything on CPU
    #[value(name = "cpu")]
    CPU,
    /// Run everything but the final proof on GPU. We consider GPU to be small if it has 24GB of VRAM.
    #[value(name = "small-gpu")]
    SmallGPU,
    /// Run everything on GPU. We consider GPU to be large if it has 32GB of VRAM or more.
    #[value(name = "large-gpu")]
    LargeGPU,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ProverRound {
    /// Run both FRI and SNARK rounds
    All {
        /// Max SNARK latency in seconds (default value - 1 hour)
        #[arg(long, default_value = "3600")]
        max_snark_latency: u64,
        /// Max amount of FRI proofs per SNARK (default value - 100)
        #[arg(long, default_value = "100")]
        max_fris_per_snark: usize,
    },
    /// Run only the FRI rounds
    Fri,
    /// Run only the SNARK rounds
    Snark,
}

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// Prover round
    #[command(subcommand)]
    pub round: ProverRound,
    /// GPU mode
    #[arg(long, default_value = "small-gpu")]
    pub gpu_mode: GPUMode,
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
    /// Directory to store the output files
    #[arg(long)]
    pub output_dir: String,
    /// Path to the trusted setup file for SNARK prover
    #[arg(long)]
    pub trusted_setup_file: Option<String>,
    /// Number of iterations (proofs) to generate before exiting
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file for FRI proofs
    #[arg(short, long)]
    pub fri_path: Option<PathBuf>,
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    match args.round {
        ProverRound::Fri => {
            let args = zksync_os_fri_prover::Args::parse();
            zksync_os_fri_prover::run(args).await?;
            Ok(())
        }
        ProverRound::Snark => {
            // TODO: edit this comment
            // we need a bigger stack, due to crypto code exhausting default stack size, 40 MBs picked here
            // note that size is not allocated, only limits the amount to which it can grow
            let stack_size = 40 * 1024 * 1024;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .thread_stack_size(stack_size)
                .enable_all()
                .build()
                .expect("failed to build tokio context");
            runtime
                .block_on(zksync_os_snark_prover::run_linking_fri_snark(
                    Some(args.base_url),
                    args.output_dir,
                    args.trusted_setup_file,
                    args.iterations,
                ))
                .expect("failed whilst running SNARK prover");
            Ok(())
        }
        ProverRound::All {
            max_snark_latency,
            max_fris_per_snark,
        } => {
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
            let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);
            
            println!(
                "Starting Zksync OS Prover Service for {}",
                client.sequencer_url()
            );

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
                while (snark_latency.elapsed().unwrap().as_secs() < max_snark_latency)
                    && (fri_proof_count < max_fris_per_snark)
                {
                    run_fri_prover(
                        &client,
                        &binary,
                        args.circuit_limit,
                        &mut gpu_state,
                        args.fri_path.clone(),
                        &mut fri_proof_count,
                    )
                    .await?;
                }

                // FIXME: do we need to drop here?
                #[cfg(feature = "gpu")]
                drop(gpu_state);
                // For regular fri proving, we keep using reduced RiscV machine.
                #[cfg(feature = "gpu")]
                let mut gpu_state = GpuSharedState::new(
                    &verifier_binary,
                    zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
                );
                #[cfg(not(feature = "gpu"))]
                let mut gpu_state = GpuSharedState::new(&verifier_binary);

                // Here we do exactly one SNARK proof
                run_snark_prover(
                    &client,
                    args.output_dir.clone(),
                    args.trusted_setup_file.clone(),
                    &mut gpu_state,
                    &verifier_binary,
                )
                .await?;
                
                // Increment SNARK proof counter
                snark_proof_count += 1;
                snark_latency = SystemTime::now();

                // Check if we've reached the iteration limit
                if let Some(max_iterations) = args.iterations {
                    if snark_proof_count >= max_iterations {
                        println!("Reached maximum iterations ({max_iterations}), exiting...",);
                        break Ok(());
                    }
                }
            }
        }
    }
}

async fn run_fri_prover(
    client: &SequencerProofClient,
    binary: &Vec<u32>,
    circuit_limit: usize,
    gpu_state: &mut GpuSharedState,
    fri_path: Option<PathBuf>,
    fri_proof_count: &mut usize,
) -> anyhow::Result<()> {
    tracing::info!("Starting FRI prover");
    let (block_number, prover_input) = match client.pick_fri_job().await {
        Err(err) => {
            eprintln!("Error fetching next prover job: {err}");
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            return Ok(());
        }
        Ok(Some(next_block)) => next_block,
        Ok(None) => {
            println!("No pending blocks to prove, retrying in 100ms...");
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            return Ok(());
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

    let proof = create_proof(prover_input, &binary, circuit_limit, gpu_state);

    *fri_proof_count += 1;

    println!(
        "{:?} finished proving block number {}",
        SystemTime::now(),
        block_number
    );
    let proof_bytes: Vec<u8> = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .expect("failed to bincode-serialize proof");

    // 2) base64-encode that binary blob
    let proof_b64 = STANDARD.encode(&proof_bytes);

    if let Some(ref path) = fri_path {
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
    };

    Ok(())
}

async fn run_snark_prover(
    client: &SequencerProofClient,
    output_dir: String,
    trusted_setup_file: Option<String>,
    gpu_state: &mut GpuSharedState,
    verifier_binary: &Vec<u32>,
) -> anyhow::Result<()> {
    tracing::info!("Starting SNARK prover");
    
    loop {
        let proof_time = Instant::now();
        tracing::info!("Started picking job");
        let snark_proof_input = match client.pick_snark_job().await {
            Ok(Some(snark_proof_input)) => {
                if snark_proof_input.fri_proofs.is_empty() {
                    let err_msg =
                        "No FRI proofs were sent, issue with Prover API/Sequencer, quitting...";
                    tracing::error!(err_msg);
                    return Err(anyhow::anyhow!(err_msg));
                }
                snark_proof_input
            }
            Ok(None) => {
                tracing::info!("No SNARK jobs found, retrying in 5s");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
            Err(e) => {
                tracing::error!("Failed to pick SNARK job due to {e:?}, retrying in 30s");
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                continue;
            }
        };
        let start_block = snark_proof_input.from_block_number;
        let end_block = snark_proof_input.to_block_number;
        tracing::info!(
            "Finished picking job, will aggregate from {} to {} inclusive",
            start_block,
            end_block
        );

        let proof = zksync_os_snark_prover::merge_fris(snark_proof_input, &verifier_binary, gpu_state);

        tracing::info!("Creating final proof before SNARKification");
        let final_proof = create_final_proofs_from_program_proof(
            proof,
            zksync_airbender_execution_utils::RecursionStrategy::UseReducedLog23Machine,
            // TODO: currently disabling GPU on final proofs, but we should have a switch in the main program
            // that allow people to run in 3 modes:
            // - cpu only
            // - small gpu (then this is false)
            // - gpu (a.k.a large gpu) - then this is true.
            false,
        );

        tracing::info!("Finished creating final proof");
        let one_fri_path = Path::new(&output_dir).join("one_fri.tmp");

        serialize_to_file(&final_proof, &one_fri_path);

        // Drop GPU state to release the airbender GPU resources (as now snark will be taking them).
        #[cfg(feature = "gpu")]
        drop(gpu_state);

        tracing::info!("SNARKifying proof");
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
                tracing::info!(
                    "SNARKification took {:?}, with total proving time being {:?}",
                    snark_time.elapsed(),
                    proof_time.elapsed()
                );
            }
            Err(e) => {
                tracing::info!("failed to SNARKify proof: {e:?}");
            }
        }
        let snark_proof: SnarkWrapperProof = zksync_os_snark_prover::deserialize_from_file(
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
                tracing::info!(
                    "Successfully submitted SNARK proof for blocks {} to {}",
                    start_block,
                    end_block
                );
            }
            Err(e) => {
                tracing::error!("Failed to submit SNARK job due to {e:?}, skipping");
            }
        };
        break;
    }

    Ok(())
}