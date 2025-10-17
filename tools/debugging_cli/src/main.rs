use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use prover_debugging_cli::fri_utils::{
    peek_fri_job_and_save, prove_fri_job_from_file, prove_fri_job_from_peek,
};
use prover_debugging_cli::snark_utils::{
    peek_snark_job_and_save, prove_snark_job_from_file, prove_snark_job_from_peek, SnarkStages,
};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(author, version, about = "ZKsync OS Prover Debugging CLI", long_about = None)]
struct Cli {
    /// Base URL of the prover API server
    #[arg(
        short,
        long,
        global = true,
        value_name = "URL",
        default_value = "http://localhost:3124"
    )]
    url: String,

    /// Activate verbose logging (`-v`, `-vv`, ...)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}
/// FRI proving parameters
#[derive(Args, Debug)]
struct FriProvingParams {
    /// Path to app.bin file
    #[arg(long, value_name = "APP_BIN_PATH")]
    app_bin_path: PathBuf,

    /// Circuit limit - max number of MainVM circuits
    #[arg(long, default_value = "10000")]
    circuit_limit: usize,

    /// Path to save the generated proof (optional)
    #[arg(short, long, value_name = "OUTPUT_PATH")]
    output_path: Option<PathBuf>,
}

/// SNARK prover stages configuration
#[derive(Args, Debug)]
struct SnarkStagesArgs {
    /// Run merge_fris stage
    #[arg(long, default_value = "true")]
    merge_fris: bool,

    /// Run final_proof stage
    #[arg(long, default_value = "true")]
    final_proof: bool,

    /// Run snarkifying stage
    #[arg(long, default_value = "true")]
    snarkifying: bool,
}

impl From<SnarkStagesArgs> for SnarkStages {
    fn from(args: SnarkStagesArgs) -> Self {
        SnarkStages {
            merge_fris: args.merge_fris,
            final_proof: args.final_proof,
            snarkifying: args.snarkifying,
        }
    }
}

/// SNARK proving parameters
#[derive(Args, Debug)]
struct SnarkProvingParams {
    /// Path to trusted setup file
    #[arg(long, value_name = "TRUSTED_SETUP_PATH")]
    trusted_setup_path: PathBuf,

    /// Directory to save output files
    #[arg(short, long, value_name = "OUTPUT_DIR", default_value = ".")]
    output_dir: PathBuf,

    #[command(flatten)]
    stages: SnarkStagesArgs,
}

#[derive(Subcommand)]
enum Commands {
    /// Peek a prover job from server and save it to file
    PeekAndSaveFriJob {
        /// Block number to peek
        #[arg(short, long, value_name = "BLOCK_NUMBER")]
        block_number: u32,

        /// Directory to save job file
        #[arg(short, long, value_name = "OUTPUT_DIR", default_value = ".")]
        output_dir: PathBuf,
    },

    /// Fetch a prover job via peek endpoint and create proof
    ProveFriJobFromPeek {
        /// Block number to fetch and prove
        #[arg(short, long, value_name = "BLOCK_NUMBER")]
        block_number: u32,

        #[command(flatten)]
        params: FriProvingParams,
    },

    /// Load a prover job from file and create proof
    ProveFriJobFromFile {
        /// Directory containing the job file
        #[arg(long, value_name = "INPUT_DIR", default_value = ".")]
        input_dir: PathBuf,

        #[command(flatten)]
        params: FriProvingParams,
    },

    /// Peek a SNARK job from server and save it to file
    PeekAndSaveSnarkJob {
        /// Starting block number
        #[arg(long, value_name = "FROM_BLOCK")]
        from_block: u32,

        /// Ending block number
        #[arg(long, value_name = "TO_BLOCK")]
        to_block: u32,

        /// Directory to save job file
        #[arg(short, long, value_name = "OUTPUT_DIR", default_value = ".")]
        output_dir: PathBuf,
    },

    /// Fetch a SNARK job via peek endpoint and create proof
    ProveSnarkJobFromPeek {
        /// Starting block number
        #[arg(long, value_name = "FROM_BLOCK")]
        from_block: u32,

        /// Ending block number
        #[arg(long, value_name = "TO_BLOCK")]
        to_block: u32,

        #[command(flatten)]
        params: SnarkProvingParams,
    },

    /// Load a SNARK job from file and create proof
    ProveSnarkJobFromFile {
        /// Directory containing the job file
        #[arg(long, value_name = "INPUT_DIR", default_value = ".")]
        input_dir: PathBuf,

        #[command(flatten)]
        params: SnarkProvingParams,
    },
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    fmt::Subscriber::builder()
        .with_env_filter(env_filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Commands::PeekAndSaveFriJob {
            block_number,
            output_dir,
        } => {
            peek_fri_job_and_save(&cli.url, block_number, &output_dir).await?;
        }
        Commands::ProveFriJobFromPeek {
            block_number,
            params,
        } => {
            prove_fri_job_from_peek(
                &cli.url,
                block_number,
                &params.app_bin_path,
                params.circuit_limit,
                params.output_path.as_deref(),
            )
            .await?;
        }
        Commands::ProveFriJobFromFile { input_dir, params } => {
            prove_fri_job_from_file(
                &input_dir,
                &params.app_bin_path,
                params.circuit_limit,
                params.output_path.as_deref(),
            )
            .await?;
        }
        Commands::PeekAndSaveSnarkJob {
            from_block,
            to_block,
            output_dir,
        } => {
            peek_snark_job_and_save(&cli.url, from_block, to_block, &output_dir).await?;
        }
        Commands::ProveSnarkJobFromPeek {
            from_block,
            to_block,
            params,
        } => {
            prove_snark_job_from_peek(
                &cli.url,
                from_block,
                to_block,
                &params.trusted_setup_path,
                &params.output_dir,
                params.stages.into(),
            )
            .await?;
        }
        Commands::ProveSnarkJobFromFile { input_dir, params } => {
            prove_snark_job_from_file(
                &input_dir,
                &params.trusted_setup_path,
                &params.output_dir,
                params.stages.into(),
            )
            .await?;
        }
    }

    Ok(())
}
