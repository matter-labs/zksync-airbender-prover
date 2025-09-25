pub mod file_based_proof_client;
pub mod sequencer_proof_client;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{fmt, time::Instant};
use zkos_wrapper::SnarkWrapperProof;
use zksync_airbender_execution_utils::ProgramProof;

use crate::metrics::{Method, SEQUENCER_CLIENT_METRICS};

mod metrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct L2BlockNumber(pub u32);

impl fmt::Display for L2BlockNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct NextFriProverJobPayload {
    block_number: u32,
    prover_input: String, // base64-encoded
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitFriProofPayload {
    block_number: u64,
    proof: String,
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
    proof: String, // base64‑encoded SNARK proof
}

impl TryInto<SnarkProofInputs> for GetSnarkProofPayload {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<SnarkProofInputs, Self::Error> {
        let mut fri_proofs = vec![];
        for encoded_proof in self.fri_proofs {
            let (fri_proof, _) = bincode::serde::decode_from_slice(
                &STANDARD.decode(encoded_proof)?,
                bincode::config::standard(),
            )?;
            fri_proofs.push(fri_proof);
        }

        Ok(SnarkProofInputs {
            from_block_number: L2BlockNumber(
                self.block_number_from
                    .try_into()
                    .expect("block_number_from should fit into L2BlockNumber(u32)"),
            ),
            to_block_number: L2BlockNumber(
                self.block_number_to
                    .try_into()
                    .expect("block_number_to should fit into L2BlockNumber(u32)"),
            ),
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

#[async_trait]
pub trait ProofClient {
    async fn pick_fri_job(&self) -> anyhow::Result<Option<(u32, Vec<u8>)>>;
    async fn submit_fri_proof(&self, block_number: u32, proof: String) -> anyhow::Result<()>;
    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>>;
    async fn submit_snark_proof(
        &self,
        from_block_number: L2BlockNumber,
        to_block_number: L2BlockNumber,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()>;
}
