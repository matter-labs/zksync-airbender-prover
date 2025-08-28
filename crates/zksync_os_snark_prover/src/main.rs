use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use zkos_wrapper::{prove, serialize_to_file, SnarkWrapperProof};
use zksync_airbender_cli::prover_utils::{
    create_final_proofs_from_program_proof, create_proofs_internal,
    generate_oracle_data_from_metadata_and_proof_list, program_proof_from_proof_list_and_metadata,
    proof_list_and_metadata_from_program_proof, GpuSharedState, MainCircuitType, RecursionStrategy,
    VerifierCircuitsIdentifiers,
};
use zksync_airbender_cli::Machine;
use zksync_airbender_execution_utils::{
    get_padded_binary, ProgramProof, UNIVERSAL_CIRCUIT_VERIFIER,
};
use zksync_sequencer_proof_client::{SequencerProofClient, SnarkProofInputs};

#[derive(Default, Debug, Serialize, Deserialize, Parser, Clone)]
pub struct SetupOptions {
    #[arg(long)]
    binary_path: String,

    #[arg(long)]
    output_dir: String,

    #[arg(long)]
    trusted_setup_file: Option<String>,
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
    },
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

fn generate_verification_key(
    binary_path: String,
    output_dir: String,
    trusted_setup_file: Option<String>,
    vk_verification_key_file: Option<String>,
) {
    match zkos_wrapper::generate_vk(Some(binary_path), output_dir, trusted_setup_file, true) {
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
                    binary_path: _,
                    output_dir,
                    trusted_setup_file,
                },
            // mode,
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
            runtime
                .block_on(run_linking_fri_snark(
                    sequencer_url,
                    output_dir,
                    trusted_setup_file,
                ))
                .expect("failed whilst running SNARK prover");
        }
    }
}

fn merge_fris(
    snark_proof_input: SnarkProofInputs,
    verifier_binary: &Vec<u32>,
    gpu_state: &mut GpuSharedState,
) -> ProgramProof {
    if snark_proof_input.fri_proofs.len() == 1 {
        tracing::info!("No proof merging needed, only one proof provided");
        return snark_proof_input.fri_proofs[0].clone();
    }
    tracing::info!("Starting proof merging");

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

        let (first_metadata, first_proof_list) = proof_list_and_metadata_from_program_proof(proof);
        let (second_metadata, second_proof_list) =
            proof_list_and_metadata_from_program_proof(second_proof);
        let first_oracle =
            generate_oracle_data_from_metadata_and_proof_list(&first_metadata, &first_proof_list);
        let second_oracle =
            generate_oracle_data_from_metadata_and_proof_list(&second_metadata, &second_proof_list);

        let mut merged_input = vec![VerifierCircuitsIdentifiers::CombinedRecursionLayers as u32];
        merged_input.extend(first_oracle);
        merged_input.extend(second_oracle);

        let (current_proof_list, proof_metadata) = create_proofs_internal(
            verifier_binary,
            merged_input,
            &Machine::Reduced,
            100, // Guessing - FIXME!!
            Some(first_metadata.create_prev_metadata()),
            &mut Some(gpu_state),
            &mut Some(0f64),
        );
        proof = program_proof_from_proof_list_and_metadata(&current_proof_list, &proof_metadata);
        tracing::info!("Finished linking proofs up to block {}", up_to_block);
    }
    // TODO: We can do a recursion step here as well, IIUC
    tracing::info!(
        "Finishing linking all proofs from {} to {}",
        snark_proof_input.from_block_number,
        snark_proof_input.to_block_number
    );
    proof
}

async fn run_linking_fri_snark(
    sequencer_url: Option<String>,
    output_dir: String,
    trusted_setup_file: Option<String>,
) -> anyhow::Result<()> {
    let sequencer_url = sequencer_url.unwrap_or("http://localhost:3124".to_string());
    let sequencer_client = SequencerProofClient::new(sequencer_url.clone());

    tracing::info!("Starting zksync_os_snark_prover");
    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);
    let mut gpu_state = GpuSharedState::new(&verifier_binary, MainCircuitType::ReducedRiscVMachine);

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

        let proof = merge_fris(snark_proof_input, &verifier_binary, &mut gpu_state);

        tracing::info!("Creating final proof before SNARKification");
        let final_proof = create_final_proofs_from_program_proof(
            proof,
            RecursionStrategy::UseReducedLog23Machine,
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
        let snark_proof: SnarkWrapperProof = deserialize_from_file(
            Path::new(&output_dir)
                .join("snark_proof.json")
                .to_str()
                .unwrap(),
        );

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
    }
}

fn deserialize_from_file<T: serde::de::DeserializeOwned>(filename: &str) -> T {
    let src = std::fs::File::open(filename).unwrap();
    serde_json::from_reader(src).unwrap()
}
