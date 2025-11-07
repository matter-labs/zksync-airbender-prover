use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use url::Url;

use crate::{
    FriJobInputs, L2BatchNumber, ProofClient,
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
        let next_index = (index + 1) % self.clients.len();
        self.current_index.store(next_index, Ordering::SeqCst);
        &self.clients[next_index]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_client_advances_and_returns_correct_index() {
        let urls = vec![
            "http://localhost:3124".parse().unwrap(),
            "http://localhost:3125".parse().unwrap(),
            "http://localhost:3126".parse().unwrap(),
        ];
        let client = MultiSequencerProofClient::new(urls);

        // Initially at index 0
        assert_eq!(client.current_index.load(Ordering::SeqCst), 0);
        assert_eq!(
            client.current_client().sequencer_url(),
            "http://localhost:3124/"
        );

        // Call next_client() - should return index 1 and advance to 1
        let returned_client = client.next_client();
        assert_eq!(returned_client.sequencer_url(), "http://localhost:3125/");
        assert_eq!(client.current_index.load(Ordering::SeqCst), 1);
        // Verify current_client() now returns the same as next_client() returned
        assert_eq!(
            client.current_client().sequencer_url(),
            "http://localhost:3125/"
        );

        // Call next_client() again - should return index 2 and advance to 2
        let returned_client = client.next_client();
        assert_eq!(returned_client.sequencer_url(), "http://localhost:3126/");
        assert_eq!(client.current_index.load(Ordering::SeqCst), 2);
        assert_eq!(
            client.current_client().sequencer_url(),
            "http://localhost:3126/"
        );

        // Call next_client() again - should wrap around to index 0
        let returned_client = client.next_client();
        assert_eq!(returned_client.sequencer_url(), "http://localhost:3124/");
        assert_eq!(client.current_index.load(Ordering::SeqCst), 0);
        assert_eq!(
            client.current_client().sequencer_url(),
            "http://localhost:3124/"
        );
    }

    #[test]
    fn test_sequencer_url_matches_current_client_after_next_client() {
        let urls = vec![
            "http://sequencer-1:3124".parse().unwrap(),
            "http://sequencer-2:3124".parse().unwrap(),
        ];
        let client = MultiSequencerProofClient::new(urls);

        // After calling next_client(), sequencer_url() should match the returned client
        for _ in 0..5 {
            let returned_client = client.next_client();
            let returned_url = returned_client.sequencer_url();
            let current_url = client.sequencer_url();
            assert_eq!(
                returned_url, current_url,
                "sequencer_url() should match the client returned by next_client()"
            );
        }
    }

    #[test]
    fn test_current_client_does_not_advance() {
        let urls = vec![
            "http://localhost:3124".parse().unwrap(),
            "http://localhost:3125".parse().unwrap(),
        ];
        let client = MultiSequencerProofClient::new(urls);

        // Call current_client() multiple times - index should not change
        assert_eq!(client.current_index.load(Ordering::SeqCst), 0);
        assert_eq!(
            client.current_client().sequencer_url(),
            "http://localhost:3124/"
        );
        assert_eq!(client.current_index.load(Ordering::SeqCst), 0);
        assert_eq!(
            client.current_client().sequencer_url(),
            "http://localhost:3124/"
        );
        assert_eq!(client.current_index.load(Ordering::SeqCst), 0);
    }
}
