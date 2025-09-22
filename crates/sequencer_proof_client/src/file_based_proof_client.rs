use std::path::PathBuf;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use zkos_wrapper::SnarkWrapperProof;

use crate::{
    GetSnarkProofPayload, L2BlockNumber, NextFriProverJobPayload, ProofClient, SnarkProofInputs,
    SubmitFriProofPayload, SubmitSnarkProofPayload,
};

#[derive(Debug)]
pub struct FileBasedProofClient {
    pub base_dir: PathBuf,
}

impl Default for FileBasedProofClient {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("../../test_data/"),
        }
    }
}

impl FileBasedProofClient {
    pub fn new(base_dir: String) -> Self {
        Self {
            base_dir: PathBuf::from(base_dir),
        }
    }

    pub fn serialize_snark_proof(&self, proof: &SnarkWrapperProof) -> anyhow::Result<String> {
        let path = self.base_dir.join("snark_proof.json");
        let mut file = std::fs::File::create(path).context("Failed to create snark_proof.json")?;
        serde_json::to_writer_pretty(&mut file, &proof)
            .context("Failed to write snark_proof.json")?;
        Ok(String::new())
    }

    pub fn serialize_fri_job(
        &self,
        block_number: u32,
        prover_input: Vec<u8>,
    ) -> anyhow::Result<()> {
        let path = self.base_dir.join("fri_job.json");
        let mut file = std::fs::File::create(path).context("Failed to create fri_job.json")?;
        serde_json::to_writer_pretty(
            &mut file,
            &NextFriProverJobPayload {
                block_number,
                prover_input: STANDARD.encode(&prover_input),
            },
        )
        .context("Failed to write fri_job.json")?;
        Ok(())
    }

    pub fn serialize_snark_job(&self, snark_proof_inputs: SnarkProofInputs) -> anyhow::Result<()> {
        let path = self.base_dir.join("snark_job.json");
        let mut file = std::fs::File::create(path).context("Failed to create snark_job.json")?;
        let fri_proofs = snark_proof_inputs
            .fri_proofs
            .iter()
            .map(|proof| {
                let proof_bytes: Vec<u8> =
                    bincode::serde::encode_to_vec(proof, bincode::config::standard())
                        .expect("failed to bincode-serialize proof");
                STANDARD.encode(&proof_bytes)
            })
            .collect::<Vec<String>>();
        serde_json::to_writer_pretty(
            &mut file,
            &GetSnarkProofPayload {
                block_number_from: snark_proof_inputs.from_block_number.0 as u64,
                block_number_to: snark_proof_inputs.to_block_number.0 as u64,
                fri_proofs,
            },
        )
        .context("Failed to write snark_job.json")?;
        Ok(())
    }
}

#[async_trait]
impl ProofClient for FileBasedProofClient {
    async fn pick_fri_job(&self) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let path = self.base_dir.join("fri_job.json");
        let file = std::fs::File::open(path).context("Failed to open fri_job.json")?;
        let fri_job: NextFriProverJobPayload =
            serde_json::from_reader(file).context("Failed to parse fri_job.json")?;
        let data = STANDARD
            .decode(&fri_job.prover_input)
            .map_err(|e| anyhow!("Failed to decode block data: {}", e))?;
        Ok(Some((fri_job.block_number, data)))
    }

    async fn submit_fri_proof(&self, block_number: u32, proof: String) -> anyhow::Result<()> {
        let path = self.base_dir.join("fri_proof.json");
        let mut file = std::fs::File::create(path).context("Failed to create fri_proof.json")?;
        let payload = SubmitFriProofPayload {
            block_number: block_number as u64,
            proof,
        };
        serde_json::to_writer_pretty(&mut file, &payload)
            .context("Failed to write fri_proof.json")?;
        Ok(())
    }

    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
        let path = self.base_dir.join("snark_job.json");
        let file = std::fs::File::open(path).context("Failed to open snark_job.json")?;
        let snark_job: GetSnarkProofPayload =
            serde_json::from_reader(file).context("Failed to parse snark_job.json")?;
        Ok(Some(snark_job.try_into()?))
    }

    async fn submit_snark_proof(
        &self,
        from_block_number: L2BlockNumber,
        to_block_number: L2BlockNumber,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()> {
        let path = self.base_dir.join("snark_proof.json");
        let mut file = std::fs::File::create(path).context("Failed to create snark_proof.json")?;
        let payload = SubmitSnarkProofPayload {
            block_number_from: from_block_number.0 as u64,
            block_number_to: to_block_number.0 as u64,
            proof: self.serialize_snark_proof(&proof)?,
        };
        serde_json::to_writer_pretty(&mut file, &payload)
            .context("Failed to write snark_proof.json")?;
        Ok(())
    }
}
