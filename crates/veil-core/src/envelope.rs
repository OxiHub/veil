//! Veil encrypted envelope format.
//!
//! Defines the wire format for encrypted payloads sent between
//! client and server. Uses MessagePack for compact serialization.

use serde::{Deserialize, Serialize};

use crate::error::{VeilError, VeilResult};

/// Protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// An encrypted Veil envelope containing an opaque payload.
///
/// This is the wire format — everything except the metadata is
/// opaque to any intermediary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VeilEnvelope {
    /// Protocol version.
    pub version: u8,

    /// AES-GCM nonce (12 bytes, base64-encoded in JSON).
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,

    /// Encrypted ciphertext with GCM tag appended.
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,

    /// Additional Authenticated Data (authenticated, not encrypted).
    /// Contains protocol metadata that must not be tampered with.
    #[serde(with = "base64_bytes")]
    pub aad: Vec<u8>,
}

impl VeilEnvelope {
    /// Create a new envelope from encryption output.
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            nonce,
            ciphertext,
            aad,
        }
    }

    /// Validate the envelope protocol version.
    ///
    /// Returns an error if the version does not match the current protocol version.
    pub fn validate(&self) -> VeilResult<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(VeilError::Envelope("unsupported protocol version".into()));
        }
        Ok(())
    }

    /// Serialize to MessagePack binary format (compact).
    pub fn to_msgpack(&self) -> VeilResult<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|e| VeilError::Envelope(format!("msgpack serialize: {e}")))
    }

    /// Deserialize from MessagePack binary format.
    pub fn from_msgpack(data: &[u8]) -> VeilResult<Self> {
        let envelope: Self = rmp_serde::from_slice(data)
            .map_err(|e| VeilError::Envelope(format!("msgpack deserialize: {e}")))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Serialize to JSON (for HTTP body transport).
    pub fn to_json(&self) -> VeilResult<String> {
        serde_json::to_string(self).map_err(|e| VeilError::Envelope(format!("json serialize: {e}")))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> VeilResult<Self> {
        let envelope: Self = serde_json::from_str(json)
            .map_err(|e| VeilError::Envelope(format!("json deserialize: {e}")))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Get the total size of the encrypted payload.
    pub fn payload_size(&self) -> usize {
        self.ciphertext.len()
    }
}

/// Metadata sent alongside the encrypted envelope in HTTP headers.
/// Visible to middleware for routing, billing, and rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VeilMetadata {
    /// Protocol version.
    pub version: u8,

    /// Server key ID used for this session.
    pub key_id: String,

    /// Client's ephemeral public key (base64).
    pub ephemeral_key: String,

    /// Target model name (for routing).
    pub model: String,

    /// Estimated token count (for billing).
    pub token_estimate: Option<u32>,

    /// Request timestamp in ISO 8601 UTC format for replay protection.
    pub timestamp: String,

    /// Unique request identifier (UUID v4) for deduplication.
    pub request_id: String,
}

impl VeilMetadata {
    /// Convert to HTTP header pairs.
    pub fn to_headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![
            ("X-Veil-Version".to_string(), self.version.to_string()),
            ("X-Veil-Key-Id".to_string(), self.key_id.clone()),
            (
                "X-Veil-Ephemeral-Key".to_string(),
                self.ephemeral_key.clone(),
            ),
            ("X-Veil-Model".to_string(), self.model.clone()),
            ("X-Veil-Timestamp".to_string(), self.timestamp.clone()),
            ("X-Veil-Request-Id".to_string(), self.request_id.clone()),
        ];

        if let Some(tokens) = self.token_estimate {
            headers.push(("X-Veil-Token-Estimate".to_string(), tokens.to_string()));
        }

        headers
    }
}

/// Custom serde module for base64-encoded byte vectors.
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_msgpack_roundtrip() {
        let env = VeilEnvelope::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            vec![0x01, 0x02],
        );

        let bytes = env.to_msgpack().unwrap();
        let restored = VeilEnvelope::from_msgpack(&bytes).unwrap();

        assert_eq!(env.version, restored.version);
        assert_eq!(env.nonce, restored.nonce);
        assert_eq!(env.ciphertext, restored.ciphertext);
        assert_eq!(env.aad, restored.aad);
    }

    #[test]
    fn test_envelope_json_roundtrip() {
        let env = VeilEnvelope::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vec![0xCA, 0xFE, 0xBA, 0xBE],
            b"veil-v1-test".to_vec(),
        );

        let json = env.to_json().unwrap();
        let restored = VeilEnvelope::from_json(&json).unwrap();

        assert_eq!(env.version, restored.version);
        assert_eq!(env.nonce, restored.nonce);
        assert_eq!(env.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_metadata_to_headers() {
        let meta = VeilMetadata {
            version: 1,
            key_id: "key-123".to_string(),
            ephemeral_key: "base64pubkey".to_string(),
            model: "gpt-4".to_string(),
            token_estimate: Some(500),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            request_id: "req-123".to_string(),
        };

        let headers = meta.to_headers();
        assert_eq!(headers.len(), 7);
        assert!(headers
            .iter()
            .any(|(k, v)| k == "X-Veil-Model" && v == "gpt-4"));
        assert!(headers
            .iter()
            .any(|(k, v)| k == "X-Veil-Timestamp" && v == "2026-01-01T00:00:00Z"));
        assert!(headers
            .iter()
            .any(|(k, v)| k == "X-Veil-Request-Id" && v == "req-123"));
    }

    #[test]
    fn test_payload_size() {
        let env = VeilEnvelope::new(vec![0; 12], vec![0; 1024], vec![]);
        assert_eq!(env.payload_size(), 1024);
    }

    #[test]
    fn test_envelope_validate_rejects_unsupported_version() {
        let mut env = VeilEnvelope::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vec![0xDE, 0xAD],
            vec![],
        );
        env.version = 99;

        let result = env.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unsupported protocol version"));
    }

    #[test]
    fn test_from_json_rejects_unsupported_version() {
        // Create a valid envelope, serialize, tamper version, try to deserialize
        let env = VeilEnvelope::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vec![0xDE, 0xAD],
            vec![],
        );
        let json = env.to_json().unwrap();
        // Replace version 1 with version 99
        let _tampered = json.replace("\"version\":1", "\"version\":99");
        // Use serde to tamper properly
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["version"] = serde_json::Value::Number(99.into());
        let tampered_json = serde_json::to_string(&val).unwrap();

        let result = VeilEnvelope::from_json(&tampered_json);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unsupported protocol version"));
    }

    #[test]
    fn test_from_msgpack_rejects_unsupported_version() {
        let mut env = VeilEnvelope::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vec![0xDE, 0xAD],
            vec![],
        );
        // Serialize with correct version first
        env.version = 99;
        // Serialize directly (bypassing validation since to_msgpack doesn't validate)
        let bytes = rmp_serde::to_vec(&env).unwrap();

        let result = VeilEnvelope::from_msgpack(&bytes);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unsupported protocol version"));
    }
}
