//! Key helpers shared by the platform FFI surfaces ([`crate::ffi`] for Apple,
//! [`crate::ffi_windows`] for Windows).
//!
//! Both GUI apps generate and inspect client keys themselves (they have no
//! `flexaccess-keys` CLI to hand the user), and the two FFI modules compile for
//! disjoint targets — so the logic lives here once instead of being copied into
//! each and left to drift.
//!
//! Errors are returned as ready-to-write messages: every caller does nothing
//! with them but copy them into the caller's output buffer.

use crate::auth::ClientKey;

/// Generate a fresh client keypair and render the key document both FFI
/// surfaces hand back:
/// `{"created":"<UTC>","public_key":"ed25519-pub:...","secret_key":"ed25519-sec:..."}`
///
/// The only failure is an unavailable system RNG.
pub fn generate_client_key_json() -> Result<String, String> {
    let key = ClientKey::generate().map_err(|e| format!("{e:#}"))?;
    Ok(serde_json::json!({
        "created": flexaccess_keys::rfc3339_utc(std::time::SystemTime::now()),
        "public_key": key.public_str(),
        "secret_key": key.secret_str(),
    })
    .to_string())
}

/// Derive the public key (`ed25519-pub:...`) of a stored secret key, so an app
/// can display it without persisting it separately.
pub fn client_public_key(secret: &str) -> Result<String, String> {
    ClientKey::from_secret_str(secret.trim())
        .map(|key| key.public_str())
        .map_err(|e| format!("invalid secret key: {e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_document_round_trips() {
        let json = generate_client_key_json().unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        let secret = doc["secret_key"].as_str().unwrap();
        let public = doc["public_key"].as_str().unwrap();
        assert!(doc["created"].as_str().is_some_and(|c| !c.is_empty()));
        // The advertised public key is the one the secret actually derives.
        assert_eq!(client_public_key(secret).unwrap(), public);
    }

    #[test]
    fn public_key_tolerates_whitespace_and_rejects_garbage() {
        let json = generate_client_key_json().unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        let secret = doc["secret_key"].as_str().unwrap();
        assert_eq!(
            client_public_key(&format!("  {secret}\n")).unwrap(),
            doc["public_key"].as_str().unwrap()
        );
        let err = client_public_key("not-a-key").unwrap_err();
        assert!(err.contains("invalid secret key"), "{err}");
    }
}
