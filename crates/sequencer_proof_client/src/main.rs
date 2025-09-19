use anyhow::{anyhow, Result};
use clap::Parser;
use tokio::sync::watch;
use zksync_sequencer_proof_client::{
    command_handler::{CommandHandler, Commands},
    metrics, SequencerProofClient,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sequencer URL to submit proofs to
    #[arg(short, long, global = true, value_name = "URL")]
    url: Option<String>,

    /// Activate verbose logging (`-v`, `-vv`, ...)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,

    /// Port to run the Prometheus metrics server on
    #[arg(long, global = true, default_value = "3312")]
    prometheus_port: u16,
}

impl Cli {
    /// Regular `::parse()`, but checks that the `--url` argument is provided & initializes tracing.
    fn init() -> Result<Self> {
        let cli = Cli::parse();
        if cli.url.is_none() {
            return Err(anyhow!("The --url <URL> argument is required. It can be placed anywhere on the command line."));
        }
        init_tracing(cli.verbose);

        Ok(cli)
    }

    /// Return sequencer client from CLI params. To be called only after `Cli::init()`.
    fn sequencer_client(&self) -> SequencerProofClient {
        SequencerProofClient::new(
            self.url
                .clone()
                .expect("called sequencer_client() before init()"),
        )
    }
}

fn init_tracing(verbosity: u8) {
    use tracing_subscriber::{fmt, EnvFilter};
    let level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    fmt::Subscriber::builder()
        .with_env_filter(env_filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::init()?;

    let (stop_sender, stop_receiver) = watch::channel(false);

    let command_handler = CommandHandler::new(cli.sequencer_client());

    tokio::select! {
        result = command_handler.handle_command(cli.command) => {
            tracing::info!("Command handler finished");
            result.expect("Command handler finished with error");
            stop_sender.send(true).expect("failed to send stop signal");
        }
        _ = metrics::start_metrics_exporter(cli.prometheus_port, stop_receiver) => {
            tracing::info!("Metrics exporter finished");
        }
    }

    Ok(())
}
