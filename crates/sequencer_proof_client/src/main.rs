use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use zkos_wrapper::SnarkWrapperProof;
use zksync_sequencer_proof_client::{L2BlockNumber, SequencerProofClient};

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

#[derive(Subcommand)]
enum Commands {
    /// Picks the next FRI proof job from the sequencer; sequencer marks job as picked (and will not give it to other clients, until the job expires)
    PickFri {
        /// Path to the FRI proof job to save
        #[arg(short, long, value_name = "FRI_PATH", default_value = "./fri_job.json")]
        path: String,
    },
    /// Submits block's FRI proof to sequencer
    SubmitFri {
        /// The block number to submit the FRI proof for
        #[arg(short, long, value_name = "BLOCK_NUMBER")]
        block_number: u32,
        /// Path to the FRI proof file to submit
        #[arg(
            short,
            long,
            value_name = "FRI_PATH",
            default_value = "./fri_proof.json"
        )]
        path: String,
    },
    /// Picks the next SNARK proof job from the sequencer; sequencer marks job as picked (and will not give it to other clients, until the job expires)
    PickSnark {
        /// Path to the SNARK proof job to save
        #[arg(
            short,
            long,
            value_name = "SNARK_PATH",
            default_value = "./snark_job.json"
        )]
        path: String,
    },
    /// Submits block's SNARK proof to sequencer
    SubmitSnark {
        /// The SNARK aggregates proofs starting from this block number
        #[arg(short, long, value_name = "FROM_BLOCK")]
        from_block_number: u32,
        /// The SNARK aggregates proofs up to this block number (inclusive)
        #[arg(short, long, value_name = "TO_BLOCK")]
        to_block_number: u32,
        /// Path to the SNARK proof file to submit
        #[arg(
            short,
            long,
            value_name = "SNARK_PATH",
            default_value = "./snark_proof.json"
        )]
        path: String,
    },
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

    let client = cli.sequencer_client();

    let url = client.sequencer_url();

    match cli.command {
        Commands::PickFri { path } => {
            tracing::info!("Picking next FRI proof job from sequencer at {}", url);
            match client.pick_fri_job().await? {
                Some((block_number, data)) => {
                    tracing::info!(
                        "Picked FRI job for block {block_number}, saved job to path {path}"
                    );
                    let mut dst = std::fs::File::create(path).unwrap();
                    serde_json::to_writer_pretty(&mut dst, &data).unwrap();
                }
                None => {
                    tracing::info!("No FRI proof jobs available at the moment.");
                }
            }
        }
        Commands::SubmitFri { block_number, path } => {
            tracing::info!("Submitting FRI proof for block {block_number} with proof from {path} to sequencer at {}", url);
            let file = std::fs::File::open(path)?;
            let fri_proof: String = serde_json::from_reader(file)?;
            client.submit_fri_proof(block_number, fri_proof).await?;
            tracing::info!(
                "Submitted FRI proof for block {block_number} to sequencer at {}",
                url
            );
        }
        Commands::PickSnark { path } => {
            tracing::info!("Picking next SNARK proof job from sequencer at {}", url);
            match client.pick_snark_job().await? {
                Some(snark_proof_inputs) => {
                    tracing::info!(
                        "Picked SNARK job for blocks [{}, {}], saved jobs to path {path}",
                        snark_proof_inputs.from_block_number,
                        snark_proof_inputs.to_block_number
                    );
                    let mut dst = std::fs::File::create(path).unwrap();
                    serde_json::to_writer_pretty(&mut dst, &snark_proof_inputs).unwrap();
                }
                None => {
                    tracing::info!("No SNARK proof jobs available at the moment.");
                }
            }
        }
        Commands::SubmitSnark {
            from_block_number,
            to_block_number,
            path,
        } => {
            tracing::info!("Submitting SNARK proof for blocks [{from_block_number}, {to_block_number}] with proof from {path} to sequencer at {}", url);
            let file = std::fs::File::open(path)?;
            let snark_wrapper: SnarkWrapperProof = serde_json::from_reader(file)?;
            client
                .submit_snark_proof(
                    L2BlockNumber(from_block_number),
                    L2BlockNumber(to_block_number),
                    snark_wrapper,
                )
                .await?;
            tracing::info!("Submitted proof for blocks [{from_block_number}, {to_block_number}] to sequencer at {}", url);
        }
    }

    Ok(())
}
