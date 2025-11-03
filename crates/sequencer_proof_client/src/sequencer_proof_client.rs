use std::time::{Duration, Instant};

use crate::metrics::Method;
use crate::{
    FailedFriProofPayload, GetSnarkProofPayload, NextFriProverJobPayload, PeekableProofClient,
    ProofClient, SnarkProofInputs, SubmitFriProofPayload, SubmitSnarkProofPayload,
};
use crate::{L2BlockNumber, SEQUENCER_CLIENT_METRICS};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bellman::{bn256::Bn256, plonk::better_better_cs::proof::Proof as PlonkProof};
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json;
use zkos_wrapper::SnarkWrapperProof;

const SEQUENCER_PROVER_API_PATH: &str = "prover-jobs/v1";

#[derive(Debug)]
pub struct SequencerProofClient {
    client: reqwest::Client,
    url: String,
}

impl SequencerProofClient {
    pub fn new(sequencer_url: String) -> Self {
        Self::new_with_timeout(sequencer_url, None)
    }

    pub fn new_with_timeout(sequencer_url: String, timeout: Option<Duration>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout.unwrap_or(Duration::from_secs(2))) // default timeout is 2 seconds
            .build()
            .expect("Failed to create reqwest client");

        Self {
            client,
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

#[derive(Debug, Serialize, Deserialize)]
struct Stuff {
    supported_vks: Vec<String>,
}

#[async_trait]
impl ProofClient for SequencerProofClient {
    /// Fetch the next block to prove.
    /// Returns `Ok(None)` if there's no block pending (204 No Content).
    async fn pick_fri_job(
        &self,
        compatible_vk_hashes: Vec<String>,
    ) -> anyhow::Result<Option<(u32, String, Vec<u8>)>> {
        let url = format!("{}/{}/FRI/pick", self.url, SEQUENCER_PROVER_API_PATH);

        let started_at = Instant::now();

        // let resp = self
        //     .client
        //     .post(&url)
        //     .json(&compatible_vk_hashes)
        //     .send()
        //     .await?;

        println!("wot?");

        let s = Stuff {
            supported_vks: compatible_vk_hashes,
        };
        let resp = self.client.post(&url).json(&s);
        println!("{resp:?}");
        let resp = resp.send().await?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::PickFri]
            .observe(started_at.elapsed().as_secs_f64());

        match resp.status() {
            StatusCode::OK => {
                let body: NextFriProverJobPayload = resp.json().await?;
                let data = STANDARD
                    .decode(&body.prover_input)
                    .map_err(|e| anyhow!("Failed to decode block data: {e}"))?;
                Ok(Some((body.block_number, body.vk_hash, data)))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!(
                "Unexpected status {s} when fetching next block at address {url}"
            )),
        }
    }

    /// Submit a proof for the processed block
    /// Returns the vector of u32 as returned by the server.
    async fn submit_fri_proof(
        &self,
        block_number: u32,
        vk_hash: String,
        proof: String,
    ) -> anyhow::Result<()> {
        let url = format!("{}/{}/FRI/submit", self.url, SEQUENCER_PROVER_API_PATH);
        let payload = SubmitFriProofPayload {
            block_number: block_number as u64,
            vk_hash,
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

    async fn pick_snark_job(
        &self,
        compatible_vk_hashes: Vec<String>,
    ) -> anyhow::Result<Option<SnarkProofInputs>> {
        let url = format!("{}/{}/SNARK/pick", self.url, SEQUENCER_PROVER_API_PATH);

        let started_at = Instant::now();
        let s = Stuff {
            supported_vks: compatible_vk_hashes,
        };
        let resp = self.client.post(&url).json(&s);
        println!("{resp:?}");
        let resp = resp.send().await?;

        // let resp = resp.send().await?;
        // let resp = self
        //     .client
        //     .post(&url)
        //     .json(&compatible_vk_hashes)
        //     .send()
        //     .await?;

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
        vk_hash: String,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()> {
        let url = format!("{}/{}/SNARK/submit", self.url, SEQUENCER_PROVER_API_PATH);

        let started_at = Instant::now();

        let serialized_proof = self
            .serialize_snark_proof(&proof)
            .context("Failed to serialize SNARK proof")?;

        let payload = SubmitSnarkProofPayload {
            block_number_from: from_block_number.0 as u64,
            block_number_to: to_block_number.0 as u64,
            vk_hash,
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

#[async_trait]
impl PeekableProofClient for SequencerProofClient {
    /// Note: you can peek only failed jobs as successful ones are removed.
    async fn peek_fri_job(&self, block_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let url = format!(
            "{}/{}/FRI/{block_number}/peek",
            self.url, SEQUENCER_PROVER_API_PATH
        );
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
            _ => Err(anyhow!(
                "Unexpected status {resp:?} when peeking the block {block_number}"
            )),
        }
    }

    async fn peek_snark_job(
        &self,
        from_block_number: u32,
        to_block_number: u32,
    ) -> anyhow::Result<Option<SnarkProofInputs>> {
        let url = format!(
            "{}/{}/SNARK/{from_block_number}/{to_block_number}/peek",
            self.url, SEQUENCER_PROVER_API_PATH
        );
        let resp = self.client.get(&url).send().await?;
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
            _ => Err(anyhow!("Unexpected status {resp:?} when peeking FRI proofs from {from_block_number} to {to_block_number}")),
        }
    }

    async fn get_failed_fri_proof(
        &self,
        block_number: u32,
    ) -> anyhow::Result<Option<FailedFriProofPayload>> {
        let url = format!(
            "{}/{}/FRI/{block_number}/failed",
            self.url, SEQUENCER_PROVER_API_PATH
        );
        let resp = self.client.get(&url).send().await?;
        match resp.status() {
            StatusCode::OK => {
                let body: FailedFriProofPayload = resp.json().await?;
                Ok(Some(body))
            }
            StatusCode::NO_CONTENT => Ok(None),
            _ => Err(anyhow!(
                "Unexpected status {resp:?} when peeking failed FRI proof for block {block_number}"
            )),
        }
    }
}
