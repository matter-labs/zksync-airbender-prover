use std::time::Duration;

use clap::Parser;
use zksync_os_prover_service::utils::{linux_peak_rss_bytes, VramMonitor};

#[tokio::main]
pub async fn main() {
    let args = zksync_os_fri_prover::Args::parse();

    let vram_mon = VramMonitor::start(Duration::from_millis(50));

    zksync_os_fri_prover::run(args).await;

    // We profile here
    let vram_available = vram_mon.available;
    let max_vram = vram_mon.stop_and_get_max();

    #[cfg(target_os = "linux")]
    let max_ram = linux_peak_rss_bytes().unwrap_or(0);

    println!(
        "max_ram_usage: {} bytes ({} MiB)",
        max_ram,
        max_ram / 1024 / 1024
    );
    if cfg!(target_os = "linux") {
        if max_vram > 0 {
            println!(
                "max_vram_usage: {} bytes ({} MiB)",
                max_vram,
                max_vram / 1024 / 1024
            );
        } else {
            if vram_available {
                println!("max_vram_usage: 0 bytes (0 MiB)  # process did not allocate VRAM");
            } else {
                println!("max_vram_usage: 0 bytes (0 MiB)  # nvidia-smi is not available");
            }
        }
    }
}
