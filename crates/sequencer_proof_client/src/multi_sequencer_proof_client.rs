use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use url::Url;

use crate::{FriJobInputs, L2BatchNumber, ProofClient, SequencerProofClient, SnarkProofInputs};
use zkos_wrapper::SnarkWrapperProof;

/// A proof client that distributes requests across multiple sequencer URLs using round-robin.
///
/// This client maintains a current index that cycles through the list of available clients,
/// ensuring load distribution across multiple sequencers.
pub struct MultiSequencerProofClient {
    clients: Vec<std::sync::Arc<dyn ProofClient + Send + Sync>>,
    current_index: AtomicUsize,
}

impl std::fmt::Debug for MultiSequencerProofClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiSequencerProofClient")
            .field("clients_count", &self.clients.len())
            .field("current_index", &self.current_index.load(Ordering::SeqCst))
            .finish()
    }
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

        let clients = urls
            .into_iter()
            .map(|url| {
                std::sync::Arc::new(SequencerProofClient::new(url))
                    as std::sync::Arc<dyn ProofClient + Send + Sync>
            })
            .collect();

        Self {
            clients,
            current_index: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub fn with_clients(clients: Vec<std::sync::Arc<dyn ProofClient + Send + Sync>>) -> Self {
        assert!(!clients.is_empty(), "At least one client must be provided");
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
            .map(|url| {
                std::sync::Arc::new(SequencerProofClient::new_with_timeout(url, timeout))
                    as std::sync::Arc<dyn ProofClient + Send + Sync>
            })
            .collect();

        Self {
            clients,
            current_index: AtomicUsize::new(0),
        }
    }

    /// Get the current client without advancing the counter.
    fn current_client(&self) -> &(dyn ProofClient + Send + Sync) {
        let index = self.current_index.load(Ordering::SeqCst);
        &*self.clients[index]
    }

    /// Get the next client in round-robin fashion (advances the counter).
    fn next_client(&self) -> &(dyn ProofClient + Send + Sync) {
        let index = self.current_index.load(Ordering::SeqCst);
        let next_index = (index + 1) % self.clients.len();
        self.current_index.store(next_index, Ordering::SeqCst);
        &*self.clients[next_index]
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

    // Mock client for testing pick and submit sequence
    struct MockProofClient {
        url: Url,
    }

    impl MockProofClient {
        fn new(url: Url) -> Self {
            Self { url }
        }
    }

    #[async_trait]
    impl ProofClient for MockProofClient {
        fn sequencer_url(&self) -> &str {
            self.url.as_str()
        }

        async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
            Ok(None)
        }

        async fn submit_fri_proof(
            &self,
            _batch_number: u32,
            vk_hash: String,
            _proof: String,
        ) -> anyhow::Result<()> {
            // Verify that the vk_hash matches this client's URL
            assert_eq!(
                vk_hash,
                self.url.to_string(),
                "Expected vk_hash to be {}, but got {}",
                self.url,
                vk_hash
            );
            Ok(())
        }

        async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
            Ok(None)
        }

        async fn submit_snark_proof(
            &self,
            _from_batch_number: L2BatchNumber,
            _to_batch_number: L2BatchNumber,
            vk_hash: String,
            _proof: SnarkWrapperProof,
        ) -> anyhow::Result<()> {
            // Verify that the vk_hash matches this client's URL
            assert_eq!(
                vk_hash,
                self.url.to_string(),
                "Expected vk_hash to be {}, but got {}",
                self.url,
                vk_hash
            );
            Ok(())
        }
    }

    // Test that FRI pick and submit happen to the same client via round-robin
    #[tokio::test]
    async fn test_fri_pick_and_submit_use_same_client() {
        let url1: Url = "http://client-1:3124".parse().unwrap();
        let url2: Url = "http://client-2:3124".parse().unwrap();
        let url3: Url = "http://client-3:3124".parse().unwrap();

        let mock1 = std::sync::Arc::new(MockProofClient::new(url1.clone()));
        let mock2 = std::sync::Arc::new(MockProofClient::new(url2.clone()));
        let mock3 = std::sync::Arc::new(MockProofClient::new(url3.clone()));

        let client = MultiSequencerProofClient::with_clients(vec![mock1, mock2, mock3]);

        let _ = client.pick_fri_job().await;
        let _ = client
            .submit_fri_proof(1, url2.to_string(), "proof".to_string())
            .await;

        let _ = client.pick_fri_job().await;
        let _ = client
            .submit_fri_proof(2, url3.to_string(), "proof".to_string())
            .await;

        let _ = client.pick_fri_job().await;
        let _ = client
            .submit_fri_proof(3, url1.to_string(), "proof".to_string())
            .await;

        // Verify the MultiSequencerProofClient internal state
        assert_eq!(client.current_index.load(Ordering::SeqCst), 0);
        // Do one more pick to verify we're back at the beginning
        let _ = client.pick_fri_job().await;
        assert_eq!(client.current_index.load(Ordering::SeqCst), 1);
    }

    // Test that SNARK pick and submit happen to the same client via round-robin
    #[tokio::test]
    async fn test_snark_pick_and_submit_use_same_client() {
        let url1: Url = "http://client-1:3124".parse().unwrap();
        let url2: Url = "http://client-2:3124".parse().unwrap();
        let url3: Url = "http://client-3:3124".parse().unwrap();

        let mock1 = std::sync::Arc::new(MockProofClient::new(url1.clone()));
        let mock2 = std::sync::Arc::new(MockProofClient::new(url2.clone()));
        let mock3 = std::sync::Arc::new(MockProofClient::new(url3.clone()));

        let client = MultiSequencerProofClient::with_clients(vec![mock1, mock2, mock3]);

        // Create a minimal dummy proof for testing - the mock client doesn't actually use it
        let dummy_proof: SnarkWrapperProof = serde_json::from_str(
            r#"{
                "n": 1,
                "inputs": [[0, 0, 0, 0]],
                "state_polys_commitments": [{"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false}],
                "witness_polys_commitments": [],
                "copy_permutation_grand_product_commitment": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false},
                "lookup_s_poly_commitment": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false},
                "lookup_grand_product_commitment": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false},
                "quotient_poly_parts_commitments": [{"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false}],
                "state_polys_openings_at_z": [[0, 0, 0, 0]],
                "state_polys_openings_at_dilations": [],
                "witness_polys_openings_at_z": [],
                "witness_polys_openings_at_dilations": [],
                "gate_setup_openings_at_z": [],
                "gate_selectors_openings_at_z": [],
                "copy_permutation_polys_openings_at_z": [[0, 0, 0, 0]],
                "copy_permutation_grand_product_opening_at_z_omega": [0, 0, 0, 0],
                "lookup_s_poly_opening_at_z_omega": [0, 0, 0, 0],
                "lookup_grand_product_opening_at_z_omega": [0, 0, 0, 0],
                "lookup_t_poly_opening_at_z": [0, 0, 0, 0],
                "lookup_t_poly_opening_at_z_omega": [0, 0, 0, 0],
                "lookup_selector_poly_opening_at_z": [0, 0, 0, 0],
                "lookup_table_type_poly_opening_at_z": [0, 0, 0, 0],
                "quotient_poly_opening_at_z": [0, 0, 0, 0],
                "linearization_poly_opening_at_z": [0, 0, 0, 0],
                "opening_proof_at_z": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false},
                "opening_proof_at_z_omega": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false}
            }"#
        ).unwrap();

        let _ = client.pick_snark_job().await;
        let _ = client
            .submit_snark_proof(
                L2BatchNumber(1),
                L2BatchNumber(2),
                url2.to_string(),
                dummy_proof.clone(),
            )
            .await;

        let _ = client.pick_snark_job().await;
        let _ = client
            .submit_snark_proof(
                L2BatchNumber(3),
                L2BatchNumber(4),
                url3.to_string(),
                dummy_proof.clone(),
            )
            .await;

        let _ = client.pick_snark_job().await;
        let _ = client
            .submit_snark_proof(
                L2BatchNumber(5),
                L2BatchNumber(6),
                url1.to_string(),
                dummy_proof.clone(),
            )
            .await;

        // Verify the MultiSequencerProofClient internal state
        assert_eq!(client.current_index.load(Ordering::SeqCst), 0);
        // Do one more pick to verify we're back at the beginning
        let _ = client.pick_snark_job().await;
        assert_eq!(client.current_index.load(Ordering::SeqCst), 1);
    }
}
