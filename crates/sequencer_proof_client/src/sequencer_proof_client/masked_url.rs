use std::fmt;
use std::ops::Deref;

use anyhow::anyhow;
use url::Url;

/// A URL wrapper that safely masks credentials when displayed.
/// Use `Deref` to access the original URL for requests, and `Display` for logging.
#[derive(Clone)]
pub struct MaskedUrl {
    url: Url,
    masked: Url,
}

impl MaskedUrl {
    pub fn new(url: Url) -> Self {
        let masked = mask_url(url.clone());
        Self { url, masked }
    }

    /// Returns a reference to the masked URL for display/logging purposes.
    pub fn masked(&self) -> &Url {
        &self.masked
    }
}

impl fmt::Debug for MaskedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show masked URL in debug output for safety
        f.debug_struct("MaskedUrl")
            .field("url", &self.masked)
            .finish()
    }
}

impl Deref for MaskedUrl {
    type Target = Url;
    fn deref(&self) -> &Url {
        &self.url
    }
}

impl fmt::Display for MaskedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.masked)
    }
}

/// Masks authentication credentials in a URL for safe logging.
/// Replaces the password with "******" if present.
fn mask_url(mut url: Url) -> Url {
    if url.password().is_some() && url.set_password(Some("******")).is_ok() {
        return url;
    }
    url
}

/// Masks a reqwest error by replacing any URL credentials with masked version.
/// Uses reqwest's structured error access to decompose and recompose the error safely.
///
/// NOTE: In testing I've noticed that reqwest strips credentials (generally).
/// However, I couldn't find this functionality documented anywhere so it might change in the future.
/// This is defensive measure in case undocumented API changes in the future.
///
/// NOTE2: The existence of `without_url` method in reqwest::Error suggests that reqwest
/// expects caller to deal with sensitive URL data themselves.
pub fn mask_reqwest_error(err: reqwest::Error) -> anyhow::Error {
    let masked_url = err.url().map(|u| MaskedUrl::new(u.clone()));
    let error_without_url = err.without_url();

    match masked_url {
        Some(url) => anyhow!("Request to {url} failed: {error_without_url}"),
        None => anyhow!("Request failed: {error_without_url}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_url_with_password() {
        let url: Url = "http://user:password123@localhost:3124".parse().unwrap();
        let masked = mask_url(url);
        assert_eq!(masked.password(), Some("******"));
        assert_eq!(masked.username(), "user");
    }

    #[test]
    fn test_mask_url_without_password() {
        let url: Url = "http://localhost:3124".parse().unwrap();
        let masked = mask_url(url.clone());
        assert_eq!(masked, url);
    }

    #[test]
    fn test_masked_url_display() {
        let url: Url = "http://user:secret@localhost:3124".parse().unwrap();
        let masked = MaskedUrl::new(url.clone());

        // Display shows masked version
        assert!(masked.to_string().contains("******"));
        assert!(!masked.to_string().contains("secret"));

        // Deref gives original
        assert_eq!(masked.password(), Some("secret"));
    }

    #[test]
    fn test_masked_url_deref() {
        let url: Url = "http://user:secret@localhost:3124/route".parse().unwrap();
        let masked = MaskedUrl::new(url);

        // Can use Deref to access original URL methods
        assert_eq!(masked.path(), "/route");
        assert_eq!(masked.host_str(), Some("localhost"));
    }

    #[tokio::test]
    async fn test_mask_reqwest_error_with_credentials() {
        let url = "http://user:secret@localhost:9999";
        // A bit nasty we can't construct an error from scratch; would love to avoid Network calls in tests
        let err = reqwest::get(url).await.unwrap_err();

        let masked = mask_reqwest_error(err);
        let error_msg = masked.to_string();

        // Should not contain actual password (reqwest may strip credentials entirely)
        assert!(
            !error_msg.contains("secret"),
            "Error should not contain actual password: {error_msg}",
        );
        // Should still contain the URL host
        assert!(
            error_msg.contains("localhost:9999"),
            "Error should contain host: {error_msg}",
        );
    }

    #[tokio::test]
    async fn test_mask_reqwest_error_without_credentials() {
        let url = "http://localhost:9999";
        let err = reqwest::get(url).await.unwrap_err();

        let masked = mask_reqwest_error(err);
        let error_msg = masked.to_string();

        // Should contain the URL
        assert!(
            error_msg.contains("localhost:9999"),
            "Error should contain host"
        );
        assert!(
            error_msg.contains("Request to"),
            "Error should have proper format"
        );
    }

    #[test]
    fn test_mask_reqwest_error_without_url() {
        // Create error without URL by using invalid proxy URL
        let err = reqwest::Proxy::all("not a valid url").unwrap_err();

        let masked = mask_reqwest_error(err);
        let error_msg = masked.to_string();

        assert!(
            error_msg.contains("Request failed:"),
            "Error should have no-URL format: {error_msg}",
        );
        assert!(
            !error_msg.contains("Request to"),
            "Error should not have URL format: {error_msg}",
        );
    }
}
