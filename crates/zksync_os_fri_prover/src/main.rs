use clap::Parser;

#[tokio::main]
pub async fn main() {
    let args = zksync_os_fri_prover::Args::parse();
    let _ = zksync_os_fri_prover::run(args).await.unwrap();
}
