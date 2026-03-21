//! Configuration for the Veil client proxy.

use serde::{Deserialize, Serialize};

/// Client proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Local address to listen on (default: 127.0.0.1:8480).
    pub listen_addr: String,

    /// Upstream Veil server URL.
    pub upstream_url: String,

    /// Server's public key (base64-encoded X25519).
    pub server_public_key: String,

    /// Server's key ID.
    pub server_key_id: String,

    /// Default model to use if not specified in request.
    pub default_model: Option<String>,

    /// Expected server public key for pinning verification (base64).
    /// If set, the proxy will reject connections if the server's
    /// public key does not match this value.
    pub expected_server_public_key: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8480".to_string(),
            upstream_url: "http://127.0.0.1:8481".to_string(),
            server_public_key: String::new(),
            server_key_id: "default".to_string(),
            default_model: None,
            expected_server_public_key: None,
        }
    }
}
