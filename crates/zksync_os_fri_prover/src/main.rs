use clap::Parser;
use tokio::sync::watch;
use zksync_sequencer_proof_client::metrics;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let args = zksync_os_fri_prover::Args::parse();

    let (stop_sender, stop_receiver) = watch::channel(false);

    let prometheus_port = args.prometheus_port;

    tokio::select! {
        _ = zksync_os_fri_prover::run(args) => {
            tracing::info!("Zksync OS FRI prover finished");
            stop_sender.send(true).expect("failed to send stop signal");
        }
        _ = metrics::start_metrics_exporter(prometheus_port, stop_receiver) => {
            tracing::info!("Metrics exporter finished");
        }
    }

    Ok(())
}
