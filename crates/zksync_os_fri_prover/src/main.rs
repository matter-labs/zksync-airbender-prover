use clap::Parser;

#[tokio::main]
pub async fn main() {
    let args = zksync_os_fri_prover::Args::parse();
    zksync_os_fri_prover::run(args).await;
}
