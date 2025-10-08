use anyhow::Context;
use clap::{Parser, Subcommand};
use zksync_os_snark_prover::{merge_fris, wrap_final_proof, WrapFinalProofArgs};

#[derive(Debug, Parser)]
#[clap(
    author,
    version,
    about = "A CLI tool for debugging and testing ZKsync operations."
)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Commands related to SNARK proofs.
    Snark(SnarkCommand),
    // More top-level commands can be added here in the future.
}

#[derive(Debug, Parser)]
pub struct SnarkCommand {
    #[clap(subcommand)]
    pub subcommand: SnarkSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SnarkSubcommand {
    /// Merges FRI proofs
    MergeFris(MergeFrisOptions),
    /// Generate Final Proof
    GenerateFinalProof(GenerateFinalProofOptions),
    /// SNARK wrapping
    SnarkWrap(SnarkWrapOptions),
}

#[derive(Debug, Parser)]
pub struct SnarkWrapOptions {
    /// Path to the input file.
    #[clap(long, required = true)]
    pub input_file: String,
    /// Path to save the final proof.
    #[clap(long, required = true)]
    pub output_dir: String,
    /// Path to trusted setup file
    #[clap(long, required = true)]
    pub trusted_setup_file: String,
}

impl SnarkWrapOptions {
    pub fn run(self) -> anyhow::Result<()> {
        let args = WrapFinalProofArgs::new(
            self.input_file,
            self.output_dir,
            Some(self.trusted_setup_file),
        );
        wrap_final_proof(args)
    }
}

#[derive(Debug, Parser)]
pub struct GenerateFinalProofOptions {
    /// Path to the input file.
    #[clap(long, required = true)]
    pub input_file: String,
    /// Path to save the final proof.
    #[clap(long, required = true)]
    pub output_file: String,
}

impl GenerateFinalProofOptions {
    pub fn run(&self) -> anyhow::Result<()> {
        let snark_input = deserialize_from_file(&self.input_file)?;
        let final_proof = zksync_os_snark_prover::generate_final_proof(snark_input);
        serialize_to_file(&final_proof, &self.output_file)
    }
}

#[derive(Debug, Parser)]
pub struct MergeFrisOptions {
    #[clap(subcommand)]
    pub source: Source,
}

impl MergeFrisOptions {
    pub fn run(&self) -> anyhow::Result<()> {
        match &self.source {
            Source::FromSequencer {
                url: _,
                batch_id: _,
                output_path: _,
            } => {
                todo!("not implemented yet");
            }
            Source::FromFile {
                input_path,
                output_path,
            } => {
                let snark_input = deserialize_from_file(input_path)?;
                let merged_proof = merge_fris(snark_input);
                serialize_to_file(&merged_proof, output_path)?;
                // Add your logic to read and merge proofs from the local file here.
            }
        }
        Ok(())
    }
}

#[derive(Debug, Subcommand)]
pub enum Source {
    /// Fetch proofs from the sequencer.
    FromSequencer {
        /// URL of the sequencer.
        #[clap(long, required = true)]
        url: String,
        /// The batch ID for which to fetch proofs.
        #[clap(long, required = true)]
        batch_id: u64,
        /// Path to save the merged proof output.
        #[clap(long, required = true)]
        output_path: String,
    },
    /// Load proofs from a local file.
    FromFile {
        /// Path to the input file containing proofs.
        #[clap(long, required = true)]
        input_path: String,
        /// Path to save the merged proof output.
        #[clap(long, required = true)]
        output_path: String,
    },
    // More mutually exclusive sources can be added here.
}

pub fn deserialize_from_file<T: serde::de::DeserializeOwned>(filename: &str) -> anyhow::Result<T> {
    let src = std::fs::File::open(filename)
        .context(format!("failed to deserialize from file {filename:?}"))?;

    serde_json::from_reader(src).map_err(|e| e.into())
}

fn serialize_to_file<T: serde::Serialize>(el: &T, filename: &str) -> anyhow::Result<()> {
    let mut dst = std::fs::File::create(filename)
        .context(format!("failed to serialize to file {filename:?}"))?;
    serde_json::to_writer_pretty(&mut dst, el)?;
    Ok(())
}
