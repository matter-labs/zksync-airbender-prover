use anyhow::{anyhow, Context};
use secrecy::SecretString;
use url::Url;

/// Internal: Credentials for authenticating with a sequencer.
#[derive(Clone)]
pub(crate) struct SequencerCredentials {
    pub(crate) username: String,
    pub(crate) password: SecretString,
}

/// A sequencer endpoint with optional credentials.
///
/// The URL is always stored without embedded credentials (user/pass stripped).
/// Any credentials found in the URL are extracted and stored separately.
#[derive(Clone)]
pub struct SequencerEndpoint {
    /// Clean URL without embedded credentials
    pub url: Url,
    /// Optional credentials for Basic Auth (internal use only)
    pub(crate) credentials: Option<SequencerCredentials>,
}

impl SequencerEndpoint {
    /// Parse a URL string into a sequencer endpoint.
    ///
    /// If the URL contains embedded credentials (e.g., `http://user:pass@host:port`),
    /// they are extracted and stored in the `credentials` field, and the URL is
    /// cleaned to remove them.
    ///
    /// # Examples
    /// ```
    /// use zksync_sequencer_proof_client::SequencerEndpoint;
    ///
    /// // Parse URL without credentials
    /// let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();
    /// assert_eq!(endpoint.url.as_str(), "http://localhost:3124/");
    ///
    /// // Parse URL with embedded credentials (they are extracted and URL is cleaned)
    /// let endpoint = SequencerEndpoint::parse("http://user:pass@localhost:3124").unwrap();
    /// assert_eq!(endpoint.url.as_str(), "http://localhost:3124/");
    /// ```
    pub fn parse(url_str: &str) -> anyhow::Result<Self> {
        let mut url = Url::parse(url_str).context("Invalid URL")?;

        // Extract credentials if present
        let credentials = if !url.username().is_empty() {
            let username = url.username().to_string();

            let password = url
                .password()
                .ok_or_else(|| anyhow!("URL has username but no password: {}", url.as_str()))?
                .to_string();

            if password.is_empty() {
                return Err(anyhow!("Password cannot be empty in URL: {}", url.as_str()));
            }

            Some(SequencerCredentials {
                username,
                password: SecretString::new(password.into()),
            })
        } else {
            None
        };

        // Strip credentials from URL
        url.set_username("").map_err(|_| {
            anyhow!("Failed to strip username from URL (URL scheme may not support credentials)")
        })?;
        url.set_password(None).map_err(|_| {
            anyhow!("Failed to strip password from URL (URL scheme may not support credentials)")
        })?;

        // Warn if using credentials over HTTP
        if credentials.is_some() && url.scheme() == "http" {
            tracing::warn!(
                "Sending credentials over unencrypted HTTP to {}. \
                 Consider using HTTPS to protect credentials in transit.",
                url.host_str().unwrap_or("unknown")
            );
        }

        Ok(Self { url, credentials })
    }
}

impl std::fmt::Debug for SequencerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("SequencerEndpoint");
        debug.field("url", &self.url.as_str());

        if let Some(creds) = &self.credentials {
            debug.field("username", &creds.username);
        } else {
            debug.field("credentials", &None::<()>);
        }

        debug.finish()
    }
}

impl std::str::FromStr for SequencerEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_without_credentials() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();

        assert_eq!(
            endpoint.url.as_str(),
            "http://localhost:3124/",
            "URL should remain unchanged when no credentials are present"
        );
        assert!(
            endpoint.credentials.is_none(),
            "Credentials should be None when URL has no credentials"
        );
    }

    #[test]
    fn test_url_with_credentials() {
        let endpoint = SequencerEndpoint::parse("http://user:password@localhost:3124").unwrap();

        // URL should be clean (credentials stripped)
        assert_eq!(
            endpoint.url.as_str(),
            "http://localhost:3124/",
            "URL should have credentials stripped"
        );
        assert_eq!(
            endpoint.url.username(),
            "",
            "URL username should be empty after stripping"
        );
        assert_eq!(
            endpoint.url.password(),
            None,
            "URL password should be None after stripping"
        );

        // Credentials should be extracted
        let creds = endpoint
            .credentials
            .as_ref()
            .expect("Credentials should be extracted");
        assert_eq!(
            creds.username, "user",
            "Username should be extracted correctly"
        );

        use secrecy::ExposeSecret;
        assert_eq!(
            creds.password.expose_secret(),
            "password",
            "Password should be extracted correctly"
        );
    }

    #[test]
    fn test_url_with_username_no_password() {
        let err = SequencerEndpoint::parse("http://user@localhost:3124").unwrap_err();
        assert!(
            err.to_string().contains("has username but no password"),
            "Error should indicate username without password: {err}",
        );
    }

    #[test]
    fn test_url_with_empty_password() {
        // Note: URL parsing treats "user:@host" the same as "user@host" - both have no password
        let err = SequencerEndpoint::parse("http://user:@localhost:3124").unwrap_err();
        assert!(
            err.to_string().contains("has username but no password"),
            "Error should indicate username without password: {err}",
        );
    }

    #[test]
    fn test_credentials_not_in_debug_output() {
        let endpoint = SequencerEndpoint::parse("http://user:secret123@localhost:3124").unwrap();
        let debug_output = format!("{endpoint:?}");

        // Should not contain actual password value
        assert!(
            !debug_output.contains("secret123"),
            "Debug output should not contain the actual password value. Got: {debug_output}"
        );

        // Should show username for troubleshooting
        assert!(
            debug_output.contains("username"),
            "Debug output should contain 'username' field. Got: {debug_output}"
        );
        assert!(
            debug_output.contains("\"user\""),
            "Debug output should show the username value. Got: {debug_output}"
        );

        // URL should be clean
        assert!(
            debug_output.contains("http://localhost:3124"),
            "Debug output should contain the clean URL. Got: {debug_output}"
        );
    }
}
