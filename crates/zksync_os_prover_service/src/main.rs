use clap::Parser;

#[tokio::main]
pub async fn main() {
    let args = zksync_os_prover_service::Args::parse();
    zksync_os_prover_service::run(args).await;
}
