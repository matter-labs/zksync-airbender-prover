use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
#[cfg(feature = "gpu")]
use zkos_wrapper::{
    generate_risk_wrapper_vk,
    gpu::{compression::get_compression_setup, snark::gpu_create_snark_setup_data},
    BoojumWorker, CompressionVK,
};
use zkos_wrapper::{prove, serialize_to_file, SnarkWrapperProof};
use zksync_airbender_cli::prover_utils::{
    create_final_proofs_from_program_proof, create_proofs_internal, GpuSharedState,
};
use zksync_airbender_execution_utils::{
    generate_oracle_data_for_universal_verifier, generate_oracle_data_from_metadata_and_proof_list,
    get_padded_binary, Machine, ProgramProof, RecursionStrategy, VerifierCircuitsIdentifiers,
    UNIVERSAL_CIRCUIT_VERIFIER,
};
use zksync_sequencer_proof_client::{SequencerProofClient, SnarkProofInputs};

use crate::metrics::SNARK_PROVER_METRICS;

mod metrics;

#[derive(Default, Debug, Serialize, Deserialize, Parser, Clone)]
pub struct SetupOptions {
    #[arg(long)]
    binary_path: String,

    #[arg(long)]
    output_dir: String,

    #[arg(long)]
    trusted_setup_file: String,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // TODO: redo this command, naming is confusing
    /// Generate the snark verification keys
    GenerateKeys {
        #[clap(flatten)]
        setup: SetupOptions,
        /// Path to the output verification key file
        #[arg(long)]
        vk_verification_key_file: Option<String>,
    },

    RunProver {
        #[arg(short, long)]
        sequencer_url: Option<String>,
        #[clap(flatten)]
        setup: SetupOptions,
        // #[arg(short, long, default_value = "linking-fris")]
        // mode: SnarkMode,
        /// Number of iterations (proofs) to generate before exiting. If not specified, runs indefinitely
        #[arg(long)]
        iterations: Option<usize>,
        /// Port to run the Prometheus metrics server on
        #[arg(long, default_value = "3124")]
        prometheus_port: u16,
    },
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

fn generate_verification_key(
    binary_path: String,
    output_dir: String,
    trusted_setup_file: String,
    vk_verification_key_file: Option<String>,
) {
    match zkos_wrapper::generate_vk(
        Some(binary_path),
        output_dir,
        Some(trusted_setup_file),
        true,
        zksync_airbender_execution_utils::RecursionStrategy::UseReducedLog23Machine,
    ) {
        Ok(key) => {
            if let Some(vk_file) = vk_verification_key_file {
                std::fs::write(vk_file, format!("{key:?}"))
                    .expect("Failed to write verification key to file");
            } else {
                tracing::info!("Verification key generated successfully: {:#?}", key);
            }
        }
        Err(e) => {
            tracing::info!("Error generating keys: {e}");
        }
    }
}

fn main() {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys {
            setup:
                SetupOptions {
                    binary_path,
                    output_dir,
                    trusted_setup_file,
                },
            vk_verification_key_file,
        } => generate_verification_key(
            binary_path,
            output_dir,
            trusted_setup_file,
            vk_verification_key_file,
        ),
        Commands::RunProver {
            sequencer_url,
            setup:
                SetupOptions {
                    binary_path,
                    output_dir,
                    trusted_setup_file,
                },
            // mode,
            iterations,
            prometheus_port,
        } => {
            // TODO: edit this comment
            // we need a bigger stack, due to crypto code exhausting default stack size, 40 MBs picked here
            // note that size is not allocated, only limits the amount to which it can grow
            let stack_size = 40 * 1024 * 1024;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .thread_stack_size(stack_size)
                .enable_all()
                .build()
                .expect("failed to build tokio context");

            let (stop_sender, stop_receiver) = watch::channel(false);

            runtime.block_on(async move {
                let metrics_handle = tokio::spawn(async move {
                    metrics::start_metrics_exporter(prometheus_port, stop_receiver).await
                });

                tokio::select! {
                    result = run_linking_fri_snark(
                        binary_path,
                        sequencer_url,
                        output_dir,
                        trusted_setup_file,
                        iterations,
                    ) => {
                        tracing::info!("SNARK prover finished");
                        result.expect("SNARK prover finished with error");
                        stop_sender.send(true).expect("failed to send stop signal");
                    }
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("Stop request received, shutting down");
                    },
                }

                match tokio::time::timeout(Duration::from_secs(10), metrics_handle).await {
                    Ok(join_result) => {
                        if let Err(join_err) = join_result {
                            tracing::warn!("metrics task panicked or was cancelled: {join_err}");
                        }
                    }
                    Err(e) => {
                        tracing::error!("Metrics exporter timed out, aborting: {e}");
                    }
                }
            });
        }
    }
}

fn merge_fris(
    snark_proof_input: SnarkProofInputs,
    verifier_binary: &Vec<u32>,
    gpu_state: &mut GpuSharedState,
) -> ProgramProof {
    let merging_time = Instant::now();

    if snark_proof_input.fri_proofs.len() == 1 {
        tracing::info!("No proof merging needed, only one proof provided");
        return snark_proof_input.fri_proofs[0].clone();
    }
    tracing::info!("Starting proof merging");

    SNARK_PROVER_METRICS
        .fri_proofs_merged
        .set(snark_proof_input.fri_proofs.len() as i64);

    let mut proof = snark_proof_input.fri_proofs[0].clone();
    for i in 1..snark_proof_input.fri_proofs.len() {
        let up_to_block = snark_proof_input.from_block_number.0 + i as u32 - 1;
        let curr_block = snark_proof_input.from_block_number.0 + i as u32;
        tracing::info!(
            "Linking proofs up to {} with proof for block {}",
            up_to_block,
            curr_block
        );
        let second_proof = snark_proof_input.fri_proofs[i].clone();

        let (first_metadata, first_proof_list) = proof.to_metadata_and_proof_list();
        let (second_metadata, second_proof_list) = second_proof.to_metadata_and_proof_list();

        let first_oracle =
            generate_oracle_data_from_metadata_and_proof_list(&first_metadata, &first_proof_list);
        let second_oracle =
            generate_oracle_data_from_metadata_and_proof_list(&second_metadata, &second_proof_list);

        let mut merged_input = vec![VerifierCircuitsIdentifiers::CombinedRecursionLayers as u32];
        merged_input.extend(first_oracle);
        merged_input.extend(second_oracle);

        let (mut current_proof_list, mut proof_metadata) = create_proofs_internal(
            verifier_binary,
            merged_input,
            &zksync_airbender_execution_utils::Machine::Reduced,
            100, // Guessing - FIXME!!
            Some(first_metadata.create_prev_metadata()),
            &mut Some(gpu_state),
            &mut Some(0f64),
        );
        // Let's do recursion.
        let mut recursion_level = 0;

        while current_proof_list.reduced_proofs.len() > 2 {
            tracing::info!("Recursion step {} after fri merging", recursion_level);
            recursion_level += 1;
            let non_determinism_data =
                generate_oracle_data_for_universal_verifier(&proof_metadata, &current_proof_list);

            (current_proof_list, proof_metadata) = create_proofs_internal(
                verifier_binary,
                non_determinism_data,
                &Machine::Reduced,
                proof_metadata.total_proofs(),
                Some(proof_metadata.create_prev_metadata()),
                &mut Some(gpu_state),
                &mut Some(0f64),
            );
        }

        proof = ProgramProof::from_proof_list_and_metadata(&current_proof_list, &proof_metadata);
        tracing::info!("Finished linking proofs up to block {}", up_to_block);
    }

    SNARK_PROVER_METRICS
        .time_taken_merge_fri
        .observe(merging_time.elapsed().as_secs_f64());

    // TODO: We can do a recursion step here as well, IIUC
    tracing::info!(
        "Finishing linking all proofs from {} to {}",
        snark_proof_input.from_block_number,
        snark_proof_input.to_block_number
    );
    proof
}

#[cfg(feature = "gpu")]
fn compute_compression_vk(binary_path: String) -> CompressionVK {
    let worker = BoojumWorker::new();

    let risc_wrapper_vk = generate_risk_wrapper_vk(
        Some(binary_path),
        true,
        RecursionStrategy::UseReducedLog23Machine,
        &worker,
    )
    .unwrap();

    let (_, compression_vk, _) = get_compression_setup(&worker, risc_wrapper_vk);
    compression_vk
}

async fn run_linking_fri_snark(
    _binary_path: String,
    sequencer_url: Option<String>,
    output_dir: String,
    trusted_setup_file: String,
    iterations: Option<usize>,
) -> anyhow::Result<()> {
    let sequencer_url = sequencer_url.unwrap_or("http://localhost:3124".to_string());
    let sequencer_client = SequencerProofClient::new(sequencer_url.clone());

    tracing::info!("Starting zksync_os_snark_prover");

    let startup_time = Instant::now();

    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    #[cfg(feature = "gpu")]
    let precomputations = {
        tracing::info!("Computing SNARK precomputations");
        let compression_vk = compute_compression_vk(_binary_path);
        let precomputations = gpu_create_snark_setup_data(compression_vk, &trusted_setup_file);
        tracing::info!("Finished computing SNARK precomputations");
        precomputations
    };

    SNARK_PROVER_METRICS
        .time_taken_startup
        .observe(startup_time.elapsed().as_secs_f64());

    let mut proof_count = 0;

    loop {
        let proof_time = Instant::now();
        tracing::info!("Started picking job");
        let snark_proof_input = match sequencer_client.pick_snark_job().await {
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
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(e) => {
                tracing::error!("Failed to pick SNARK job due to {e:?}, retrying in 30s");
                tokio::time::sleep(Duration::from_secs(30)).await;
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
        tracing::info!("Initializing GPU state");
        #[cfg(feature = "gpu")]
        let mut gpu_state = GpuSharedState::new(
            &verifier_binary,
            zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
        );
        #[cfg(not(feature = "gpu"))]
        let mut gpu_state = GpuSharedState::new(&verifier_binary);
        tracing::info!("Finished initializing GPU state");
        let proof = merge_fris(snark_proof_input, &verifier_binary, &mut gpu_state);

        // Drop GPU state to release the airbender GPU resources (as now Final Proof will be taking them).
        #[cfg(feature = "gpu")]
        drop(gpu_state);

        tracing::info!("Creating final proof before SNARKification");
        let final_proof_time = Instant::now();
        let final_proof = create_final_proofs_from_program_proof(
            proof,
            RecursionStrategy::UseReducedLog23Machine,
            // TODO: currently enabled GPU on final proofs, but we should have a switch in the main program
            // that allow people to run in 3 modes:
            // - cpu only
            // - small gpu (then this is false)
            // - gpu (a.k.a large gpu) - then this is true.
            // NOTE: use this as false, if you want to run on a small GPU
            true,
        );

        SNARK_PROVER_METRICS
            .time_taken_final_proof
            .observe(final_proof_time.elapsed().as_secs_f64());

        tracing::info!("Finished creating final proof");
        let one_fri_path = Path::new(&output_dir).join("one_fri.tmp");

        serialize_to_file(&final_proof, &one_fri_path);

        tracing::info!("SNARKifying proof");
        let snark_time = Instant::now();
        match prove(
            one_fri_path.into_os_string().into_string().unwrap(),
            output_dir.clone(),
            Some(trusted_setup_file.clone()),
            false,
            #[cfg(feature = "gpu")]
            Some(precomputations.clone()),
        ) {
            Ok(()) => {
                tracing::info!(
                    "SNARKification took {:?}, with total proving time being {:?}",
                    snark_time.elapsed(),
                    proof_time.elapsed()
                );
                SNARK_PROVER_METRICS
                    .time_taken_snark
                    .observe(snark_time.elapsed().as_secs_f64());
                SNARK_PROVER_METRICS
                    .time_taken_full
                    .observe(proof_time.elapsed().as_secs_f64());
            }
            Err(e) => {
                tracing::info!("failed to SNARKify proof: {e:?}");
            }
        }
        let snark_proof: SnarkWrapperProof = deserialize_from_file(
            Path::new(&output_dir)
                .join("snark_proof.json")
                .to_str()
                .unwrap(),
        );

        SNARK_PROVER_METRICS
            .latest_proven_block
            .set(end_block.0 as i64);

        match sequencer_client
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

        proof_count += 1;

        if let Some(max_iterations) = iterations {
            if proof_count >= max_iterations {
                tracing::info!("Reached maximum iterations ({max_iterations}), exiting...");
                return Ok(());
            }
        }
    }
}

fn deserialize_from_file<T: serde::de::DeserializeOwned>(filename: &str) -> T {
    let src = std::fs::File::open(filename).unwrap();
    serde_json::from_reader(src).unwrap()
}
