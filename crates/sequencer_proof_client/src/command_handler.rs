use clap::Subcommand;
use zkos_wrapper::SnarkWrapperProof;

use crate::{L2BlockNumber, SequencerProofClient};

pub struct CommandHandler {
    client: SequencerProofClient,
    sequencer_url: String,
}

impl CommandHandler {
    pub fn new(client: SequencerProofClient) -> Self {
        let sequencer_url = client.sequencer_url().to_string();
        Self {
            client,
            sequencer_url,
        }
    }

    pub async fn handle_command(&self, command: Commands) -> anyhow::Result<()> {
        match command {
            Commands::PickFri { path } => {
                self.pick_fri_job(path).await?;
            }
            Commands::SubmitFri { block_number, path } => {
                self.submit_fri_proof(block_number, path).await?;
            }
            Commands::PickSnark { path } => {
                self.pick_snark_job(path).await?;
            }
            Commands::SubmitSnark {
                from_block_number,
                to_block_number,
                path,
            } => {
                self.submit_snark_proof(from_block_number, to_block_number, path)
                    .await?;
            }
        }
        Ok(())
    }

    async fn pick_fri_job(&self, path: String) -> anyhow::Result<()> {
        tracing::info!(
            "Picking next FRI proof job from sequencer at {}",
            self.sequencer_url
        );
        match self.client.pick_fri_job().await? {
            Some((block_number, data)) => {
                tracing::info!("Picked FRI job for block {block_number}, saved job to path {path}");
                let mut dst = std::fs::File::create(path).unwrap();
                serde_json::to_writer_pretty(&mut dst, &data).unwrap();
            }
            None => {
                tracing::info!("No FRI proof jobs available at the moment.");
            }
        }
        Ok(())
    }

    async fn submit_fri_proof(&self, block_number: u32, path: String) -> anyhow::Result<()> {
        tracing::info!(
            "Submitting FRI proof for block {block_number} with proof from {path} to sequencer at {}",
            self.sequencer_url
        );
        let file = std::fs::File::open(path)?;
        let fri_proof: String = serde_json::from_reader(file)?;
        self.client
            .submit_fri_proof(block_number, fri_proof)
            .await?;
        tracing::info!(
            "Submitted FRI proof for block {block_number} to sequencer at {}",
            self.sequencer_url
        );
        Ok(())
    }

    async fn pick_snark_job(&self, path: String) -> anyhow::Result<()> {
        tracing::info!(
            "Picking next SNARK proof job from sequencer at {}",
            self.sequencer_url
        );
        match self.client.pick_snark_job().await? {
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
        Ok(())
    }

    async fn submit_snark_proof(
        &self,
        from_block_number: u32,
        to_block_number: u32,
        path: String,
    ) -> anyhow::Result<()> {
        tracing::info!("Submitting SNARK proof for blocks [{from_block_number}, {to_block_number}] with proof from {path} to sequencer at {}", self.sequencer_url);
        let file = std::fs::File::open(path)?;
        let snark_wrapper: SnarkWrapperProof = serde_json::from_reader(file)?;
        self.client
            .submit_snark_proof(
                L2BlockNumber(from_block_number),
                L2BlockNumber(to_block_number),
                snark_wrapper,
            )
            .await?;
        tracing::info!(
            "Submitted proof for blocks [{from_block_number}, {to_block_number}] to sequencer at {}",
            self.sequencer_url
        );

        Ok(())
    }
}

#[derive(Subcommand)]
pub enum Commands {
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
