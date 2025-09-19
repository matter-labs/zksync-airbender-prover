use std::net::Ipv4Addr;

use tokio::sync::watch;
use vise::{Metrics, MetricsCollection};
use vise_exporter::MetricsExporter;

pub async fn start_metrics_exporter(
    port: u16,
    mut stop_receiver: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let registry = MetricsCollection::lazy().collect();
    let metrics_exporter =
        MetricsExporter::new(registry.into()).with_graceful_shutdown(async move {
            stop_receiver.changed().await.ok();
        });

    let prom_bind_address = (Ipv4Addr::UNSPECIFIED, port).into();
    metrics_exporter
        .start(prom_bind_address)
        .await
        .map_err(|e| anyhow::anyhow!("Failed starting metrics server: {}", e))?;

    Ok(())
}

#[derive(Debug, Clone, Metrics)]
#[metrics(prefix = "fri_prover")]
pub struct FriProverMetrics {}

pub(crate) static FRI_PROVER_METRICS: vise::Global<FriProverMetrics> = vise::Global::new();
