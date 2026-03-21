import textwrap

content = textwrap.dedent("""\
    //! HKDF-SHA256 key derivation for the Veil protocol.
    //!
    //! Derives separate encryption keys for each direction (client->server,
    //! server->client) from the ECDH shared secret.

    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::SharedSecret;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use crate::error::{VeilError, VeilResult};

    const KEY_LEN: usize = 32;
    const PROTOCOL_SALT: &[u8] = b\"veil-e2e-llm-v1\";
    const PROTOCOL_SALT_V2: &[u8] = b\"veil-e2e-llm-v2-prekey\";
    const CLIENT_TO_SERVER_INFO: &[u8] = b\"veil-c2s\";
    const SERVER_TO_CLIENT_INFO: &[u8] = b\"veil-s2c\";

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct SessionKeys {
        pub client_to_server: [u8; KEY_LEN],
        pub server_to_client: [u8; KEY_LEN],
    }
""")
print(content[:200])
