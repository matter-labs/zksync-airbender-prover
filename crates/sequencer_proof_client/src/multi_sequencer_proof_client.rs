use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Url;

use crate::{
    FailedFriProofPayload, FriJobInputs, L2BatchNumber, PeekableProofClient, ProofClient,
    SequencerProofClient, SnarkProofInputs,
};
use zkos_wrapper::SnarkWrapperProof;

/// A proof client that distributes requests across multiple sequencer URLs using round-robin.
///
/// This client maintains a current index that cycles through the list of available clients,
/// ensuring load distribution across multiple sequencers.
#[derive(Debug)]
pub struct MultiSequencerProofClient {
    clients: Vec<SequencerProofClient>,
    current_index: AtomicUsize,
}

impl MultiSequencerProofClient {
    /// Create a new `MultiSequencerProofClient` with a list of sequencer URLs.
    ///
    /// # Arguments
    /// * `urls` - A vector of sequencer URLs
    ///
    /// # Panics
    /// Panics if the urls vector is empty
    pub fn new(urls: Vec<Url>) -> Self {
        assert!(
            !urls.is_empty(),
            "At least one sequencer URL must be provided"
        );

        tracing::info!(
            "Initializing MultiSequencerProofClient with {} sequencer(s):",
            urls.len()
        );
        for url in &urls {
            tracing::info!("  - {}", url);
        }

        let clients = urls.into_iter().map(SequencerProofClient::new).collect();

        Self {
            clients,
            current_index: AtomicUsize::new(0),
        }
    }

    /// Create a new `MultiSequencerProofClient` with a list of sequencer URLs and custom timeout.
    ///
    /// # Arguments
    /// * `urls` - A vector of sequencer URLs
    /// * `timeout` - Optional timeout for HTTP requests
    ///
    /// # Panics
    /// Panics if the urls vector is empty
    pub fn new_with_timeout(urls: Vec<Url>, timeout: Option<Duration>) -> Self {
        assert!(
            !urls.is_empty(),
            "At least one sequencer URL must be provided"
        );

        tracing::info!(
            "Initializing MultiSequencerProofClient with {} sequencer(s):",
            urls.len()
        );
        for url in &urls {
            tracing::info!("  - {}", url);
        }

        let clients = urls
            .into_iter()
            .map(|url| SequencerProofClient::new_with_timeout(url, timeout))
            .collect();

        Self {
            clients,
            current_index: AtomicUsize::new(0),
        }
    }

    /// Get the current client without advancing the counter.
    fn current_client(&self) -> &SequencerProofClient {
        let index = self.current_index.load(Ordering::SeqCst);
        &self.clients[index]
    }

    /// Get the next client in round-robin fashion (advances the counter).
    fn next_client(&self) -> &SequencerProofClient {
        let index = self.current_index.load(Ordering::SeqCst);
        self.current_index
            .store((index + 1) % self.clients.len(), Ordering::SeqCst);
        &self.clients[index]
    }
}

#[async_trait]
impl ProofClient for MultiSequencerProofClient {
    fn sequencer_url(&self) -> &str {
        self.current_client().sequencer_url()
    }

    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
        self.next_client().pick_fri_job().await
    }

    async fn submit_fri_proof(
        &self,
        batch_number: u32,
        vk_hash: String,
        proof: String,
    ) -> anyhow::Result<()> {
        self.current_client()
            .submit_fri_proof(batch_number, vk_hash, proof)
            .await
    }

    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
        self.next_client().pick_snark_job().await
    }

    async fn submit_snark_proof(
        &self,
        from_batch_number: L2BatchNumber,
        to_batch_number: L2BatchNumber,
        vk_hash: String,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()> {
        self.current_client()
            .submit_snark_proof(from_batch_number, to_batch_number, vk_hash, proof)
            .await
    }
}

#[async_trait]
impl PeekableProofClient for MultiSequencerProofClient {
    async fn peek_fri_job(&self, batch_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        self.current_client().peek_fri_job(batch_number).await
    }

    async fn peek_snark_job(
        &self,
        from_batch_number: u32,
        to_batch_number: u32,
    ) -> anyhow::Result<Option<SnarkProofInputs>> {
        self.current_client()
            .peek_snark_job(from_batch_number, to_batch_number)
            .await
    }

    async fn get_failed_fri_proof(
        &self,
        batch_number: u32,
    ) -> anyhow::Result<Option<FailedFriProofPayload>> {
        self.current_client()
            .get_failed_fri_proof(batch_number)
            .await
    }
}
