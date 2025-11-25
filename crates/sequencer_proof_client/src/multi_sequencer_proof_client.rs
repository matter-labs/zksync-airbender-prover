use std::sync::Mutex;

use async_trait::async_trait;
use url::Url;

use crate::{FriJobInputs, L2BatchNumber, ProofClient, SnarkProofInputs};
use zkos_wrapper::SnarkWrapperProof;

/// A proof client that distributes requests across multiple sequencer URLs using round-robin.
///
/// This client maintains a current index that cycles through the list of available clients.
/// The caller is responsible for calling `advance_index()` to rotate to the next client.
///
/// # Usage Pattern
///
/// ```ignore
/// loop {
///     let result = client.pick_fri_job().await?;
///     if let Some(job) = result {
///         // Process and submit job
///     }
///     client.advance_index();  // Rotate to next sequencer
/// }
/// ```
///
/// Call `advance_index()` to rotate to the next sequencer in the pool.
/// Typical strategies:
/// - Advance after each iteration (distributes load evenly)
/// - Advance only on `None`/errors (sticky on success)
/// - Custom rotation policy based on your needs
pub struct MultiSequencerProofClient {
    clients: Vec<Box<dyn ProofClient + Send + Sync>>,
    current_index: Mutex<usize>,
}

impl std::fmt::Debug for MultiSequencerProofClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("MultiSequencerProofClient");
        debug.field(
            "clients",
            &format_args!(
                "[{}]",
                self.clients
                    .iter()
                    .map(|c| format!("ProofClient(\"{}\")", c.sequencer_url()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        debug.field(
            "current_index",
            &*self
                .current_index
                .lock()
                .expect("current_index mutex poisoned"),
        );
        debug.finish()
    }
}

impl MultiSequencerProofClient {
    /// Create a new `MultiSequencerProofClient` with a list of sequencer URLs.
    ///
    /// # Arguments
    /// * `clients` - A vector of sequencer client implementations
    pub fn new(clients: Vec<Box<dyn ProofClient + Send + Sync>>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !clients.is_empty(),
            "At least one sequencer client must be provided"
        );

        tracing::info!(
            "Initializing MultiSequencerProofClient with {} sequencer(s):",
            clients.len()
        );
        for c in clients.iter() {
            tracing::info!("  - {}", c.sequencer_url());
        }

        Ok(Self {
            clients,
            current_index: Mutex::new(0),
        })
    }

    /// Get the current client without advancing the counter.
    fn current_client(&self) -> &(dyn ProofClient + Send + Sync) {
        let index = *self
            .current_index
            .lock()
            .expect("current_index mutex poisoned");
        &*self.clients[index]
    }

    /// Advance the index to the next client in round-robin fashion.
    /// Call this method to rotate to next sequencer.
    ///
    /// NOTE: Requires manual invocation by the caller to control rotation policy.
    pub fn advance_index(&self) {
        let mut index = self
            .current_index
            .lock()
            .expect("current_index mutex poisoned");
        *index = (*index + 1) % self.clients.len();
    }
}

#[async_trait]
impl ProofClient for MultiSequencerProofClient {
    fn sequencer_url(&self) -> Url {
        self.current_client().sequencer_url()
    }

    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
        self.current_client().pick_fri_job().await
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
        self.current_client().pick_snark_job().await
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

    // Mock client for testing pick and submit sequence
    struct MockProofClient {
        url: Url,
    }

    impl MockProofClient {
        fn new(url: Url) -> Self {
            Self { url }
        }

        fn new_clients(urls: Vec<Url>) -> Vec<Box<dyn ProofClient + Send + Sync>> {
            urls.into_iter()
                .map(|url| {
                    Box::new(MockProofClient::new(url)) as Box<dyn ProofClient + Send + Sync>
                })
                .collect()
        }
    }

    #[async_trait]
    impl ProofClient for MockProofClient {
        fn sequencer_url(&self) -> Url {
            self.url.clone()
        }

        async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
            Ok(None)
        }

        async fn submit_fri_proof(
            &self,
            _batch_number: u32,
            _vk_hash: String,
            _proof: String,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
            Ok(None)
        }

        async fn submit_snark_proof(
            &self,
            _from_batch_number: L2BatchNumber,
            _to_batch_number: L2BatchNumber,
            _vk_hash: String,
            _proof: SnarkWrapperProof,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_advance_index_wraps_around() {
        let urls = vec![
            "http://client-1.com".parse().unwrap(),
            "http://client-2.com".parse().unwrap(),
            "http://client-3.com".parse().unwrap(),
        ];
        let multi_client =
            MultiSequencerProofClient::new(MockProofClient::new_clients(urls.clone())).unwrap();

        // Verify wrapping through multiple cycles
        for cycle in 0..2 {
            for (i, url) in urls.iter().enumerate() {
                assert_eq!(
                    multi_client.sequencer_url(),
                    url,
                    "cycle {cycle}, index {i}",
                );
                multi_client.advance_index();
            }
        }
        // Should be back at start
        assert_eq!(multi_client.sequencer_url(), &urls[0]);
    }

    #[tokio::test]
    async fn test_operations_stay_on_same_client_without_advance() {
        let urls = vec![
            "http://client-1.com".parse().unwrap(),
            "http://client-2.com".parse().unwrap(),
        ];
        let multi_client =
            MultiSequencerProofClient::new(MockProofClient::new_clients(urls.clone())).unwrap();

        // Multiple operations on same client without advancing
        let url_before = multi_client.sequencer_url().clone();

        multi_client.pick_fri_job().await.unwrap();
        assert_eq!(multi_client.sequencer_url(), &url_before);

        multi_client
            .submit_fri_proof(1, "vk".to_string(), "proof".to_string())
            .await
            .unwrap();
        assert_eq!(multi_client.sequencer_url(), &url_before);

        // Now advance - should move to next client
        multi_client.advance_index();
        assert_eq!(multi_client.sequencer_url(), &urls[1]);
        assert_ne!(multi_client.sequencer_url(), &url_before);
    }
}
