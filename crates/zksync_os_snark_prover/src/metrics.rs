use std::{net::Ipv4Addr, time::Duration};

use tokio::{sync::watch, time::Instant};
use vise::{Counter, Gauge, Histogram, Metrics, MetricsCollection};
use vise_exporter::MetricsExporter;

pub async fn start_metrics_exporter(
    port: u16,
    mut stop_receiver: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tracing::info!("Starting metrics exporter on port {port}");
    let registry = MetricsCollection::lazy().collect();
    let metrics_exporter =
        MetricsExporter::new(registry.into()).with_graceful_shutdown(async move {
            stop_receiver.changed().await.ok();
        });

    let prom_bind_address = (Ipv4Addr::UNSPECIFIED, port).into();
    metrics_exporter
        .start(prom_bind_address)
        .await
        .map_err(|e| anyhow::anyhow!("Failed starting metrics server: {e}"))?;

    Ok(())
}

#[derive(Debug, Clone, Metrics)]
#[metrics(prefix = "snark_prover")]
pub struct SnarkProverMetrics {
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_startup: Histogram,
    #[metrics(buckets = vise::Buckets::linear(1.0..=150.0, 20.0), unit = vise::Unit::Seconds)]
    pub time_taken_merge_fri: Histogram,
    #[metrics(buckets = vise::Buckets::linear(5.0..=20.0, 2.5), unit = vise::Unit::Seconds)]
    pub time_taken_final_proof: Histogram,
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_snark: Histogram,
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_full: Histogram,
    pub fri_proofs_merged: Gauge,
    pub latest_proven_batch: Gauge,
    /// Number of timeout errors when communicating with sequencer
    pub timeout_errors: Counter,
}

#[vise::register]
pub(crate) static SNARK_PROVER_METRICS: vise::Global<SnarkProverMetrics> = vise::Global::new();

pub(crate) struct SnarkProofTimeStats {
    pub time_taken_merge_fri: Duration,
    pub time_taken_final_proof: Duration,
    pub time_taken_snark: Duration,
}

impl std::fmt::Display for SnarkProofTimeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Merge FRI: {:?}\n", self.time_taken_merge_fri)?;
        write!(f, "Final Proof: {:?}\n", self.time_taken_final_proof)?;
        write!(f, "SNARK: {:?}\n", self.time_taken_snark)?;
        write!(
            f,
            "Total: {:?}\n",
            self.time_taken_merge_fri + self.time_taken_final_proof + self.time_taken_snark
        )?;
        Ok(())
    }
}

impl SnarkProofTimeStats {
    pub fn new() -> Self {
        Self {
            time_taken_merge_fri: Duration::from_secs(0),
            time_taken_final_proof: Duration::from_secs(0),
            time_taken_snark: Duration::from_secs(0),
        }
    }

    pub fn measure_step<F, T>(target: &mut Duration, step: F) -> T
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = step();
        *target += start.elapsed();
        result
    }

    pub fn observe(&self) {
        SNARK_PROVER_METRICS
            .time_taken_merge_fri
            .observe(self.time_taken_merge_fri.as_secs_f64());
        SNARK_PROVER_METRICS
            .time_taken_final_proof
            .observe(self.time_taken_final_proof.as_secs_f64());
        SNARK_PROVER_METRICS
            .time_taken_snark
            .observe(self.time_taken_snark.as_secs_f64());
        SNARK_PROVER_METRICS.time_taken_full.observe(
            (self.time_taken_merge_fri + self.time_taken_final_proof + self.time_taken_snark)
                .as_secs_f64(),
        );
    }
}
