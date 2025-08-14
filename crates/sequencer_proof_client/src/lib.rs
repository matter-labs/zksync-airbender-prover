// TODO: Add testing around this

use std::fmt;
use anyhow::{anyhow, Context};
use base64::Engine;
use base64::engine::general_purpose;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use zkos_wrapper::SnarkWrapperProof;
use zksync_airbender_execution_utils::ProgramProof;
use bellman::{bn256::Bn256, plonk::better_better_cs::proof::Proof as PlonkProof};
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord
)]
pub struct L2BlockNumber(pub u32);

impl fmt::Display for L2BlockNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GetSnarkProofPayload {
    block_number_from: u64,
    block_number_to: u64,
    fri_proofs: Vec<String>, // base64‑encoded FRI proofs
}


#[derive(Debug, Serialize, Deserialize)]
struct SubmitSnarkProofPayload {
    block_number_from: u64,
    block_number_to: u64,
    proof: String, // base64‑encoded FRI proofs
}

impl TryInto<SnarkProofInputs> for GetSnarkProofPayload {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<SnarkProofInputs, Self::Error> {
        let mut fri_proofs = vec![];
        for encoded_proof in self.fri_proofs {
            let fri_proof = bincode::deserialize(&base64::decode(encoded_proof)?)?;
            fri_proofs.push(fri_proof);
        }

        Ok(SnarkProofInputs {
            from_block_number: L2BlockNumber(self.block_number_from.try_into().expect("block_number_from should fit into L2BlockNumber(u32)")),
            to_block_number: L2BlockNumber(self.block_number_to.try_into().expect("block_number_to should fit into L2BlockNumber(u32)")),
            fri_proofs,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnarkProofInputs {
    pub from_block_number: L2BlockNumber,
    pub to_block_number: L2BlockNumber,
    pub fri_proofs: Vec<ProgramProof>,
}

#[derive(Debug)]
pub struct SequencerProofClient {
    client: reqwest::Client,
    url: String,
}

impl SequencerProofClient {
    pub fn new(sequencer_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: sequencer_url,
        }
    }

    pub fn sequencer_url(&self) -> &str {
        &self.url
    }

    pub async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
        let url = format!("{}/prover-jobs/SNARK/pick", self.url);
        let resp = self.client.post(&url).send().await?;
        match resp.status() {
            StatusCode::OK => {
                let get_snark_proof_payload = resp.json::<GetSnarkProofPayload>().await?;
                Ok(Some(get_snark_proof_payload.try_into().context("failed to parse SnarkProofPayload")?))
            }
            StatusCode::NO_CONTENT => {
                Ok(None)
            }
            _ => {
                Err(anyhow!("Failed to pick SNARK job: {:?}", resp))
            }
        }
    }

    pub async fn submit_snark_proof(&self, from_block_number: L2BlockNumber, to_block_number: L2BlockNumber, proof: SnarkWrapperProof) -> anyhow::Result<()> {
        let url = format!("{}/prover-jobs/SNARK/submit", self.url);

        let serialized_proof = self.serialize_snark_proof(&proof)
            .context("Failed to serialize SNARK proof")?;

        let payload = SubmitSnarkProofPayload {
            block_number_from: from_block_number.0 as u64,
            block_number_to: to_block_number.0 as u64,
            proof: general_purpose::STANDARD.encode(&serialized_proof),
        };
        self.client
            .post(&url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    fn serialize_snark_proof(&self, proof: &SnarkWrapperProof) -> anyhow::Result<String> {
        let serialized_proof = serde_json::to_string(&proof)?;

        let codegen_snark_proof: PlonkProof<Bn256, ZkSyncSnarkWrapperCircuit> =
            serde_json::from_str(&serialized_proof)?;
        let (_, serialized_proof) = crypto_codegen::serialize_proof(&codegen_snark_proof);

        let mut byte_serialized_proof = vec![];
        for val in serialized_proof.iter() {
            let mut buf = [0u8; 32];
            val.to_big_endian(&mut buf);
            byte_serialized_proof.extend_from_slice(&buf);
        }
        let serialized = bincode::serialize(proof)?;
        Ok(general_purpose::STANDARD.encode(serialized))
    }
}