use std::path::PathBuf;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use zkos_wrapper::SnarkWrapperProof;

use crate::{
    FailedFriProofPayload, GetSnarkProofPayload, L2BlockNumber, NextFriProverJobPayload,
    ProofClient, SnarkProofInputs, SubmitFriProofPayload, SubmitSnarkProofPayload,
};

const FRI_JOB_FILE: &str = "fri_job.json";
const FRI_PROOF_FILE: &str = "fri_proof.json";
const SNARK_JOB_FILE: &str = "snark_job.json";
const SNARK_PROOF_FILE: &str = "snark_proof.json";
const FAILED_FRI_PROOF_FILE: &str = "failed_fri_proof.json";

// FileBasedProofClient stores proof jobs and proofs in files, useful for local testing.
#[derive(Debug)]
pub struct FileBasedProofClient {
    pub base_dir: PathBuf,
}

impl Default for FileBasedProofClient {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("../../outputs/"),
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
        let path = self.base_dir.join(SNARK_PROOF_FILE);
        let mut file =
            std::fs::File::create(path).context(format!("Failed to create {SNARK_PROOF_FILE}"))?;
        serde_json::to_writer_pretty(&mut file, &proof)
            .context(format!("Failed to write {SNARK_PROOF_FILE}"))?;
        Ok(String::new())
    }

    pub fn serialize_fri_job(&self, block_number: u32, prover_input: &[u8]) -> anyhow::Result<()> {
        let path = self.base_dir.join(FRI_JOB_FILE);
        let mut file =
            std::fs::File::create(path).context(format!("Failed to create {FRI_JOB_FILE}"))?;
        serde_json::to_writer_pretty(
            &mut file,
            &NextFriProverJobPayload {
                block_number,
                prover_input: STANDARD.encode(prover_input),
            },
        )
        .context(format!("Failed to write {FRI_JOB_FILE}"))?;
        Ok(())
    }

    pub fn serialize_snark_job(&self, snark_proof_inputs: &SnarkProofInputs) -> anyhow::Result<()> {
        let path = self.base_dir.join(SNARK_JOB_FILE);
        let mut file =
            std::fs::File::create(path).context(format!("Failed to create {SNARK_JOB_FILE}"))?;
        serde_json::to_writer_pretty(&mut file, &snark_proof_inputs)
            .context(format!("Failed to write {SNARK_JOB_FILE}"))?;
        Ok(())
    }

    pub fn serialize_failed_fri_proof(
        &self,
        failed_fri_proof: &FailedFriProofPayload,
    ) -> anyhow::Result<()> {
        let path = self.base_dir.join(FAILED_FRI_PROOF_FILE);
        let mut file = std::fs::File::create(path)
            .context(format!("Failed to create {FAILED_FRI_PROOF_FILE}"))?;
        serde_json::to_writer_pretty(&mut file, &failed_fri_proof)
            .context(format!("Failed to write {FAILED_FRI_PROOF_FILE}"))?;
        Ok(())
    }

    pub fn deserialize_failed_fri_proof(&self) -> anyhow::Result<FailedFriProofPayload> {
        let path = self.base_dir.join(FAILED_FRI_PROOF_FILE);
        let file =
            std::fs::File::open(path).context(format!("Failed to open {FAILED_FRI_PROOF_FILE}"))?;
        let failed_fri_proof: FailedFriProofPayload = serde_json::from_reader(file)
            .context(format!("Failed to parse {FAILED_FRI_PROOF_FILE}"))?;
        Ok(failed_fri_proof)
    }
}

#[async_trait]
impl ProofClient for FileBasedProofClient {
    async fn pick_fri_job(&self) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let path = self.base_dir.join(FRI_JOB_FILE);
        let file = std::fs::File::open(path).context(format!("Failed to open {FRI_JOB_FILE}"))?;
        let fri_job: NextFriProverJobPayload =
            serde_json::from_reader(file).context(format!("Failed to parse {FRI_JOB_FILE}"))?;
        let data = STANDARD
            .decode(&fri_job.prover_input)
            .map_err(|e| anyhow!("Failed to decode block data: {e}"))?;
        Ok(Some((fri_job.block_number, data)))
    }

    async fn submit_fri_proof(&self, block_number: u32, proof: String) -> anyhow::Result<()> {
        let path = self.base_dir.join(FRI_PROOF_FILE);
        let mut file =
            std::fs::File::create(path).context(format!("Failed to create {FRI_PROOF_FILE}"))?;
        let payload = SubmitFriProofPayload {
            block_number: block_number as u64,
            proof,
        };
        serde_json::to_writer_pretty(&mut file, &payload)
            .context(format!("Failed to write {FRI_PROOF_FILE}"))?;
        Ok(())
    }

    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
        let path = self.base_dir.join(SNARK_JOB_FILE);
        let file = std::fs::File::open(path).context(format!("Failed to open {SNARK_JOB_FILE}"))?;
        let snark_job: GetSnarkProofPayload =
            serde_json::from_reader(file).context(format!("Failed to parse {SNARK_JOB_FILE}"))?;
        Ok(Some(snark_job.try_into()?))
    }

    async fn submit_snark_proof(
        &self,
        from_block_number: L2BlockNumber,
        to_block_number: L2BlockNumber,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()> {
        let path = self.base_dir.join(SNARK_PROOF_FILE);
        let mut file =
            std::fs::File::create(path).context(format!("Failed to create {SNARK_PROOF_FILE}"))?;
        let payload = SubmitSnarkProofPayload {
            block_number_from: from_block_number.0 as u64,
            block_number_to: to_block_number.0 as u64,
            proof: self.serialize_snark_proof(&proof)?,
        };
        serde_json::to_writer_pretty(&mut file, &payload)
            .context(format!("Failed to write {SNARK_PROOF_FILE}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sequencer_proof_client::SequencerProofClient, PeekableProofClient};

    #[tokio::test]
    #[ignore]
    async fn test_file_based_proof_client_peek_fri_job() {
        let block_number = 598;
        let sequencer_proof_client = SequencerProofClient::new("http://localhost:3124".to_string());
        let file_based_proof_client = FileBasedProofClient::new("../../outputs/".to_string());
        let (block_number, data_from_sequencer) = sequencer_proof_client
            .peek_fri_job(block_number)
            .await
            .unwrap()
            .unwrap();
        file_based_proof_client
            .serialize_fri_job(block_number, &data_from_sequencer)
            .unwrap();
        let (block_number, data) = file_based_proof_client
            .pick_fri_job()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(block_number, block_number);
        assert_eq!(data, data_from_sequencer);
    }

    #[tokio::test]
    #[ignore]
    async fn test_file_based_proof_client_peek_snark_job() {
        let from_block_number = 580;
        let to_block_number = 582;
        let sequencer_proof_client = SequencerProofClient::new("http://localhost:3124".to_string());
        let file_based_proof_client = FileBasedProofClient::new("../../outputs/".to_string());
        let snark_proof_inputs_from_sequencer = sequencer_proof_client
            .peek_snark_job(from_block_number, to_block_number)
            .await
            .unwrap()
            .unwrap();
        file_based_proof_client
            .serialize_snark_job(&snark_proof_inputs_from_sequencer)
            .unwrap();
        let snark_proof_inputs = file_based_proof_client
            .pick_snark_job()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            snark_proof_inputs.from_block_number,
            snark_proof_inputs_from_sequencer.from_block_number
        );
        assert_eq!(
            snark_proof_inputs.to_block_number,
            snark_proof_inputs_from_sequencer.to_block_number
        );
        assert_eq!(
            snark_proof_inputs.fri_proofs.len(),
            snark_proof_inputs_from_sequencer.fri_proofs.len()
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_file_based_proof_client_peek_failed_fri_proof() {
        let block_number = 598;
        let sequencer_proof_client = SequencerProofClient::new("http://localhost:3124".to_string());
        let file_based_proof_client = FileBasedProofClient::new("../../outputs/".to_string());
        let failed_fri_proof_from_sequencer = sequencer_proof_client
            .get_failed_fri_proof(block_number)
            .await
            .unwrap()
            .unwrap();
        file_based_proof_client
            .serialize_failed_fri_proof(&failed_fri_proof_from_sequencer)
            .unwrap();
        let failed_fri_proof = file_based_proof_client
            .deserialize_failed_fri_proof()
            .unwrap();
        assert_eq!(
            failed_fri_proof.batch_number,
            failed_fri_proof_from_sequencer.batch_number
        );
        assert_eq!(
            failed_fri_proof.proof,
            failed_fri_proof_from_sequencer.proof
        );
    }
}
