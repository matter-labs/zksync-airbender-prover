use std::time::Instant;

use crate::metrics::Method;
use crate::{
    GetSnarkProofPayload, NextFriProverJobPayload, ProofClient, SnarkProofInputs,
    SubmitFriProofPayload, SubmitSnarkProofPayload,
};
use crate::{L2BlockNumber, SEQUENCER_CLIENT_METRICS};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bellman::{bn256::Bn256, plonk::better_better_cs::proof::Proof as PlonkProof};
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit;
use reqwest::StatusCode;
use serde_json;
use zkos_wrapper::SnarkWrapperProof;

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

    pub fn serialize_snark_proof(&self, proof: &SnarkWrapperProof) -> anyhow::Result<String> {
        let serialized_proof = serde_json::to_string(&proof)?;

        let codegen_snark_proof: PlonkProof<Bn256, ZkSyncSnarkWrapperCircuit> =
            serde_json::from_str(&serialized_proof)?;
        let (_, serialized_proof) = crypto_codegen::serialize_proof(&codegen_snark_proof);

        let byte_serialized_proof = serialized_proof
            .iter()
            .flat_map(|chunk| {
                let mut buf = [0u8; 32];
                chunk.to_big_endian(&mut buf);
                buf
            })
            .collect::<Vec<u8>>();

        Ok(STANDARD.encode(byte_serialized_proof))
    }
}

#[async_trait]
impl ProofClient for SequencerProofClient {
    async fn peek_fri_job(&self, block_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let url = format!("{}/prover-jobs/FRI/{block_number}/peek", self.url);
        let resp = self.client.get(&url).send().await?;
        match resp.status() {
            StatusCode::OK => {
                let body: NextFriProverJobPayload = resp.json().await?;
                let data = STANDARD
                    .decode(&body.prover_input)
                    .map_err(|e| anyhow!("Failed to decode block data: {e}"))?;
                Ok(Some((body.block_number, data)))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!("Unexpected status {s} when peeking next block")),
        }
    }

    /// Fetch the next block to prove.
    /// Returns `Ok(None)` if there's no block pending (204 No Content).
    async fn pick_fri_job(&self) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let url = format!("{}/prover-jobs/FRI/pick", self.url);

        let started_at = Instant::now();

        let resp = self.client.post(&url).send().await?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::PickFri]
            .observe(started_at.elapsed().as_secs_f64());

        match resp.status() {
            StatusCode::OK => {
                let body: NextFriProverJobPayload = resp.json().await?;
                let data = STANDARD
                    .decode(&body.prover_input)
                    .map_err(|e| anyhow!("Failed to decode block data: {e}"))?;
                Ok(Some((body.block_number, data)))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!("Unexpected status {s} when fetching next block")),
        }
    }

    /// Submit a proof for the processed block
    /// Returns the vector of u32 as returned by the server.
    async fn submit_fri_proof(&self, block_number: u32, proof: String) -> anyhow::Result<()> {
        let url = format!("{}/prover-jobs/FRI/submit", self.url);
        let payload = SubmitFriProofPayload {
            block_number: block_number as u64,
            proof,
        };

        let started_at = Instant::now();

        let resp = self.client.post(&url).json(&payload).send().await?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::SubmitFri]
            .observe(started_at.elapsed().as_secs_f64());

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Server returned {} when submitting proof",
                resp.status()
            ))
        }
    }

    async fn peek_fri_proofs(
        &self,
        from_block_number: u32,
        to_block_number: u32,
    ) -> anyhow::Result<Option<SnarkProofInputs>> {
        let url = format!(
            "{}/prover-jobs/SNARK/{from_block_number}/{to_block_number}/peek",
            self.url
        );
        let resp = self.client.get(&url).send().await?;
        match resp.status() {
            StatusCode::OK => {
                let body: GetSnarkProofPayload = resp.json().await?;
                Ok(Some(body.try_into()?))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!("Unexpected status {s} when peeking FRI proofs")),
        }
    }

    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
        let url = format!("{}/prover-jobs/SNARK/pick", self.url);

        let started_at = Instant::now();

        let resp = self.client.post(&url).send().await?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::PickSnark]
            .observe(started_at.elapsed().as_secs_f64());

        match resp.status() {
            StatusCode::OK => {
                let get_snark_proof_payload = resp.json::<GetSnarkProofPayload>().await?;
                Ok(Some(
                    get_snark_proof_payload
                        .try_into()
                        .context("failed to parse SnarkProofPayload")?,
                ))
            }
            StatusCode::NO_CONTENT => Ok(None),
            _ => Err(anyhow!("Failed to pick SNARK job: {resp:?}")),
        }
    }

    async fn submit_snark_proof(
        &self,
        from_block_number: L2BlockNumber,
        to_block_number: L2BlockNumber,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()> {
        let url = format!("{}/prover-jobs/SNARK/submit", self.url);

        let started_at = Instant::now();

        let serialized_proof = self
            .serialize_snark_proof(&proof)
            .context("Failed to serialize SNARK proof")?;

        let payload = SubmitSnarkProofPayload {
            block_number_from: from_block_number.0 as u64,
            block_number_to: to_block_number.0 as u64,
            proof: serialized_proof,
        };
        self.client
            .post(&url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::SubmitSnark]
            .observe(started_at.elapsed().as_secs_f64());
        Ok(())
    }
}
