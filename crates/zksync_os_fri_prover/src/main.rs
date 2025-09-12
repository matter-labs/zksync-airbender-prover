use clap::Parser;


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
    /// Number of iterations (proofs) to generate before exiting. If not specified, runs indefinitely
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file
    #[arg(short, long)]
    pub path: Option<PathBuf>,
}

#[tokio::main]
pub async fn main() {
    let args = zksync_os_fri_prover::Args::parse();
    zksync_os_fri_prover::run(args).await;
}
