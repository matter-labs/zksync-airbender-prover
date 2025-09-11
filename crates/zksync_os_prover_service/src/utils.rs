use std::fs;
use std::hint::black_box;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

/// -------- RAM peak (Linux): read VmHWM from /proc/self/status --------
#[cfg(target_os = "linux")]
pub fn linux_peak_rss_bytes() -> std::io::Result<u64> {
    let s = fs::read_to_string("/proc/self/status")?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            // format: "VmHWM:\t  123456 kB"
            let kb: u64 = rest
                .split_whitespace()
                .nth(0) // number
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            return Ok(kb * 1024);
        }
    }
    // For safety, fallback: read current VmRSS.
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .nth(0)
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            return Ok(kb * 1024);
        }
    }
    Ok(0)
}

/// -------- VRAM peak (NVIDIA): poll `nvidia-smi` every N ms --------
pub struct VramMonitor {
    stop: Arc<AtomicBool>,
    max_bytes: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
    pub available: bool,
}

impl VramMonitor {
    pub fn start(poll_every: Duration) -> Self {
        let available = Command::new("nvidia-smi")
            .arg("-h")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let stop = Arc::new(AtomicBool::new(false));
        let max_bytes = Arc::new(AtomicU64::new(0));

        let handle = if available {
            let stop_c = Arc::clone(&stop);
            let max_c = Arc::clone(&max_bytes);
            let pid = std::process::id().to_string();
            Some(thread::spawn(move || {
                // Request pid,used_memory in MiB without header/units
                let args = [
                    "--query-compute-apps=pid,used_memory",
                    "--format=csv,noheader,nounits",
                ];
                while !stop_c.load(Ordering::Relaxed) {
                    if let Ok(out) = Command::new("nvidia-smi").args(args).output() {
                        if out.status.success() {
                            let stdout = String::from_utf8_lossy(&out.stdout);
                            // The same PID can appear on multiple GPUs — sum them.
                            let mut total_mib: u64 = 0;
                            for line in stdout.lines() {
                                let mut cols = line.split(',').map(|s| s.trim());
                                let pid_col = cols.next().unwrap_or("");
                                let mem_col = cols.next().unwrap_or("");
                                if pid_col == pid {
                                    if let Ok(mib) = mem_col.parse::<u64>() {
                                        total_mib = total_mib.saturating_add(mib);
                                    }
                                }
                            }
                            let bytes = total_mib.saturating_mul(1024 * 1024);
                            // update maximum
                            loop {
                                let prev = max_c.load(Ordering::Relaxed);
                                if bytes <= prev {
                                    break;
                                }
                                if max_c
                                    .compare_exchange(
                                        prev,
                                        bytes,
                                        Ordering::Relaxed,
                                        Ordering::Relaxed,
                                    )
                                    .is_ok()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    thread::sleep(poll_every);
                }
            }))
        } else {
            None
        };

        Self {
            stop,
            max_bytes,
            handle,
            available,
        }
    }

    pub fn stop_and_get_max(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle {
            let _ = h.join();
        }
        self.max_bytes.load(Ordering::Relaxed)
    }
}

mod tests {
    use super::*;
    #[test]
    fn test_ram_vram_usage() {
        // Start VRAM monitor (poll every 200 ms)
        let vram_mon = VramMonitor::start(Duration::from_millis(200));

        // -------- YOUR CODE/LOAD ----------
        // Demonstration: expand RAM to ~512 MiB for a couple of seconds.
        let mut data = vec![0u8; 2 * 512 * 1024 * 1024];
        for i in (0..data.len()).step_by(4096) {
            data[i] = 1; // touch pages, so we actually do something
        }
        black_box(&data);

        thread::sleep(Duration::from_secs(2));
        drop(data);

        // Here may be your GPU work (CUDA/ROCm and etc.).
        // VRAM monitor is already running and will catch the peak if the process uses GPU memory.

        // ------------------------------------

        // Take the peak VRAM and read the peak RAM
        let vram_available = vram_mon.available;
        let max_vram = vram_mon.stop_and_get_max();

        #[cfg(target_os = "linux")]
        let max_ram = linux_peak_rss_bytes().unwrap_or(0);

        // Print in a convenient format
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

    use crate::utils::{linux_peak_rss_bytes, VramMonitor};
    use clap::Parser;
    use std::time::Duration;

    #[tokio::test]
    pub async fn test_prover_service_ram_vram_usage() {
        let args = crate::Args::parse();

        let vram_mon = VramMonitor::start(Duration::from_millis(50));

        let _ = crate::run(args).await;

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
}
