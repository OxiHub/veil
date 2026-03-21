//! End-to-end integration tests for the Veil protocol.

use veil_core::keys::StaticKeyPair;
use veil_core::session::{ClientSession, ServerSession};

#[test]
fn test_full_e2e_roundtrip() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut client_session =
        ClientSession::new(&server_pub, "test-key").expect("Failed to create client session");

    let prompt = b"{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}";
    let (envelope, metadata) = client_session
        .encrypt_request(prompt, "gpt-4", Some(10))
        .expect("Failed to encrypt request");

    assert_eq!(metadata.model, "gpt-4");
    assert_eq!(metadata.token_estimate, Some(10));
    assert_eq!(metadata.key_id, "test-key");
    assert!(!metadata.ephemeral_key.is_empty());
    assert!(!metadata.timestamp.is_empty());
    assert!(!metadata.request_id.is_empty());

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key, "test-key", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    let decrypted = server_session
        .decrypt_request(&envelope)
        .expect("Failed to decrypt request");
    assert_eq!(decrypted, prompt);

    let response = b"{\"choices\":[{\"message\":{\"content\":\"Hello back!\"}}]}";
    let response_envelope = server_session
        .encrypt_response(response)
        .expect("Failed to encrypt response");

    let decrypted_response = client_session
        .decrypt_response(&response_envelope)
        .expect("Failed to decrypt response");
    assert_eq!(decrypted_response, response);
}

#[test]
fn test_different_sessions_produce_different_ciphertext() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut session_a = ClientSession::new(&server_pub, "key-1").expect("Failed to create session A");
    let mut session_b = ClientSession::new(&server_pub, "key-1").expect("Failed to create session B");

    let prompt = b"secret prompt";

    let (envelope_a, _meta_a) = session_a
        .encrypt_request(prompt, "model", None)
        .expect("Failed to encrypt");

    let (envelope_b, _meta_b) = session_b
        .encrypt_request(prompt, "model", None)
        .expect("Failed to encrypt");

    // Different sessions should produce different ciphertexts
    assert_ne!(
        envelope_a.ciphertext, envelope_b.ciphertext,
        "Different sessions should produce different ciphertexts"
    );
}

#[test]
fn test_cross_session_decryption_works() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let prompt = b"secret prompt";
    let (envelope, meta) = session
        .encrypt_request(prompt, "model", None)
        .expect("Failed to encrypt");

    // Server creates session from the ephemeral key
    let server_session = ServerSession::new(&server_kp, &meta.ephemeral_key, "key-1", &meta.request_id, &meta.timestamp)
        .expect("Failed to create server session");

    let decrypted = server_session
        .decrypt_request(&envelope)
        .expect("Should decrypt with correct ephemeral key");
    assert_eq!(decrypted, prompt);
}

#[test]
fn test_large_payload_e2e() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    // 1MB payload (large context window)
    let large_prompt: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let mut session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let (envelope, metadata) = session
        .encrypt_request(&large_prompt, "gpt-4-turbo", Some(50000))
        .expect("Failed to encrypt large payload");

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key, "key-1", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    let decrypted = server_session
        .decrypt_request(&envelope)
        .expect("Failed to decrypt large payload");

    assert_eq!(decrypted, large_prompt);
}

#[test]
fn test_tampered_ciphertext_rejected() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let (mut envelope, metadata) = session
        .encrypt_request(b"secret", "model", None)
        .expect("Failed to encrypt");

    // Tamper with the ciphertext
    if let Some(byte) = envelope.ciphertext.last_mut() {
        *byte ^= 0xFF;
    }

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key, "key-1", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    assert!(
        server_session.decrypt_request(&envelope).is_err(),
        "Tampered ciphertext should be rejected"
    );
}

#[test]
fn test_tampered_nonce_rejected() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let (mut envelope, metadata) = session
        .encrypt_request(b"secret", "model", None)
        .expect("Failed to encrypt");

    // Tamper with the nonce
    if let Some(byte) = envelope.nonce.first_mut() {
        *byte ^= 0xFF;
    }

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key, "key-1", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    assert!(
        server_session.decrypt_request(&envelope).is_err(),
        "Tampered nonce should be rejected"
    );
}

#[test]
fn test_wrong_server_key_rejected() {
    let server_kp_real = StaticKeyPair::generate();
    let server_kp_fake = StaticKeyPair::generate();

    let mut session = ClientSession::new(&server_kp_real.public_base64(), "key-1")
        .expect("Failed to create session");

    let (envelope, metadata) = session
        .encrypt_request(b"secret", "model", None)
        .expect("Failed to encrypt");

    let wrong_session = ServerSession::new(&server_kp_fake, &metadata.ephemeral_key, "key-1", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    assert!(
        wrong_session.decrypt_request(&envelope).is_err(),
        "Wrong server key should fail to decrypt"
    );
}

#[test]
fn test_encrypt_decrypt_chunk_roundtrip() {
    // Full roundtrip: client encrypt_chunk -> server decrypt_chunk
    // Verifies the streaming API pair is symmetric and correct.
    let server_kp = veil_core::keys::StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut client = veil_core::session::ClientSession::new(&server_pub, "key-1").unwrap();
    let plaintext = b"streaming chunk content";
    let stream_id = "stream-abc-123";
    let chunk_index = 5u64;
    let is_final = false;
    // Client encrypts chunk
    let (envelope, meta) = client
        .encrypt_chunk(plaintext, "gpt-4", stream_id, chunk_index, is_final)
        .expect("encrypt_chunk failed");
    // Verify metadata fields are set correctly
    assert_eq!(meta.stream_id.as_deref(), Some(stream_id));
    assert_eq!(meta.chunk_index, Some(chunk_index));
    assert_eq!(meta.is_final_chunk, Some(is_final));
    // Server creates session from client metadata
    let server = veil_core::session::ServerSession::new(
        &server_kp,
        &meta.ephemeral_key,
        &meta.key_id,
        &meta.request_id,
        &meta.timestamp,
    ).expect("ServerSession::new failed");
    // Server decrypts chunk with correct stream position
    let decrypted = server
        .decrypt_chunk(&envelope, stream_id, chunk_index, is_final)
        .expect("decrypt_chunk failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_decrypt_chunk_rejects_wrong_index() {
    // Server must reject chunk with wrong chunk_index (reorder attack).
    let server_kp = veil_core::keys::StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut client = veil_core::session::ClientSession::new(&server_pub, "key-1").unwrap();
    let (envelope, meta) = client
        .encrypt_chunk(b"chunk at index 0", "gpt-4", "stream-1", 0, false)
        .expect("encrypt failed");
    let server = veil_core::session::ServerSession::new(
        &server_kp,
        &meta.ephemeral_key,
        &meta.key_id,
        &meta.request_id,
        &meta.timestamp,
    ).expect("server session failed");
    // Attempt to decrypt as chunk index 1 (wrong!) must fail
    let result = server.decrypt_chunk(&envelope, "stream-1", 1, false);
    assert!(result.is_err(), "Should reject chunk with wrong index — reorder attack detected");
}
