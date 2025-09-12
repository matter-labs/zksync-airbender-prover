use clap::Parser;


/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// Max SNARK latency in seconds (default value - 1 hour)
    #[arg(long, default_value = "3600", conflicts_with = "max_fris_per_snark")]
    max_snark_latency: Option<u64>,
    /// Max amount of FRI proofs per SNARK (default value - 100)
    #[arg(long, default_value = "100", conflicts_with = "max_snark_latency")]
    max_fris_per_snark: Option<usize>,
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
    /// Directory to store the output files for SNARK prover
    #[arg(long)]
    pub output_dir: String,
    /// Path to the trusted setup file for SNARK prover
    #[arg(long)]
    pub trusted_setup_file: Option<String>,
    /// Number of iterations (SNARK proofs) to generate before exiting
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file for FRI proofs
    #[arg(short, long)]
    pub fri_path: Option<PathBuf>,
}

#[tokio::main]
pub async fn main() {
    let args = zksync_os_prover_service::Args::parse();
    zksync_os_prover_service::run(args).await;
}
