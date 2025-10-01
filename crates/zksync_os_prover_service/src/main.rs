use clap::Parser;
use zksync_os_prover_service::init_tracing;

#[tokio::main]
pub async fn main() {
    init_tracing();
    let args = zksync_os_prover_service::Args::parse();
    zksync_os_prover_service::run(args).await;
}
