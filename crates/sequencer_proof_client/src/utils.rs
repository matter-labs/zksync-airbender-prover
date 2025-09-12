use std::path::PathBuf;

use anyhow::Context;
use zkos_wrapper::SnarkWrapperProof;

use crate::{L2BlockNumber, ProofClient, SnarkProofInputs};

#[derive(Debug)]
pub struct FileBasedProofClient {
    base_dir: PathBuf,
}

impl ProofClient for FileBasedProofClient {
    fn new(base_dir: String) -> Self {
        Self {
            base_dir: PathBuf::from(base_dir),
        }
    }

    fn sequencer_url(&self) -> &str {
        self.base_dir.to_str().unwrap()
    }

    async fn pick_fri_job(
        &self,
    ) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let block_number = 0;
        let path = self.base_dir.join("fri_job.json");
        let file = std::fs::File::open(path).context("Failed to open fri_job.json")?;
        let fri_job: Vec<u8> =
            serde_json::from_reader(file).context("Failed to parse fri_job.json")?;
        Ok(Some((block_number, fri_job)))
    }

    async fn submit_fri_proof(
        &self,
        _block_number: u32,
        proof: String,
    ) -> anyhow::Result<()> {
        let path = self.base_dir.join("fri_proof.json");
        let mut file =
            std::fs::File::create(path).context("Failed to create fri_proof.json")?;
        serde_json::to_writer_pretty(&mut file, &proof)
            .context("Failed to write fri_proof.json")?;
        Ok(())
    }

    async fn pick_snark_job(
        &self,
    ) -> anyhow::Result<Option<SnarkProofInputs>> {
        let path = self.base_dir.join("snark_job.json");
        let file = std::fs::File::open(path).context("Failed to open snark_job.json")?;
        let snark_job: SnarkProofInputs =
            serde_json::from_reader(file).context("Failed to parse snark_job.json")?;
        Ok(Some(snark_job))
    }

    async fn submit_snark_proof(
        &self,
        _from_block_number: L2BlockNumber,
        _to_block_number: L2BlockNumber,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()> {
        let path = self.base_dir.join("snark_proof.json");
        let mut file =
            std::fs::File::create(path).context("Failed to create snark_proof.json")?;
        serde_json::to_writer_pretty(&mut file, &proof)
            .context("Failed to write snark_proof.json")?;
        Ok(())
    }

    fn serialize_snark_proof(&self, proof: &SnarkWrapperProof) -> anyhow::Result<String> {
        let path = self.base_dir.join("snark_proof.json");
        let mut file = std::fs::File::create(path).context("Failed to create snark_proof.json")?;
        serde_json::to_writer_pretty(&mut file, &proof)
            .context("Failed to write snark_proof.json")?;
        Ok(String::new())
    }
}
