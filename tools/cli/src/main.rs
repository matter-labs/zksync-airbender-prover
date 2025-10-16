use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};
use zksync_airbender_prover_cli::fri_utils::{
    peek_fri_job_and_save, prove_fri_job_from_file, prove_fri_job_from_peek,
};

#[derive(Parser)]
#[command(author, version, about = "ZKsync OS Prover CLI", long_about = None)]
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

        /// Path to app.bin file
        #[arg(long, value_name = "APP_BIN_PATH")]
        app_bin_path: PathBuf,

        /// Circuit limit - max number of MainVM circuits
        #[arg(long, default_value = "10000")]
        circuit_limit: usize,

        /// Path to save the generated proof (optional)
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        output_path: Option<PathBuf>,
    },

    /// Load a prover job from file and create proof
    ProveFriJobFromFile {
        /// Block number (used to find fri_job_{block_number}.json)
        #[arg(short, long, value_name = "BLOCK_NUMBER")]
        block_number: u32,

        /// Directory containing the job file
        #[arg(long, value_name = "INPUT_DIR", default_value = ".")]
        input_dir: PathBuf,

        /// Path to app.bin file
        #[arg(long, value_name = "APP_BIN_PATH")]
        app_bin_path: PathBuf,

        /// Circuit limit - max number of MainVM circuits
        #[arg(long, default_value = "10000")]
        circuit_limit: usize,

        /// Path to save the generated proof (optional)
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        output_path: Option<PathBuf>,
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
            app_bin_path,
            circuit_limit,
            output_path,
        } => {
            prove_fri_job_from_peek(
                &cli.url,
                block_number,
                &app_bin_path,
                circuit_limit,
                output_path.as_deref(),
            )
            .await?;
        }
        Commands::ProveFriJobFromFile {
            block_number,
            input_dir,
            app_bin_path,
            circuit_limit,
            output_path,
        } => {
            prove_fri_job_from_file(
                block_number,
                &input_dir,
                &app_bin_path,
                circuit_limit,
                output_path.as_deref(),
            )
            .await?;
        }
    }

    Ok(())
}
