use std::collections::HashMap;

use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;

/// Value shipped in `.env.example`; refusing it stops people from running with published secrets.
pub const PLACEHOLDER: &str = "change-me";

pub struct Config {
    pub port: u16,
    pub postgrest_url: String,
    /// Verification keys by `kid`; the gateway never holds a signing key.
    pub keys: HashMap<String, DecodingKey>,
}

/// Reads config through `get` so tests don't have to mutate the process environment.
pub fn load(get: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
    let jwks_raw = required(&get, "KILNBASE_JWKS")?;
    let jwks: JwkSet = serde_json::from_str(&jwks_raw)
        .map_err(|e| format!("KILNBASE_JWKS is not a valid JWK set: {e}"))?;
    let mut keys = HashMap::new();
    for jwk in &jwks.keys {
        let kid = jwk
            .common
            .key_id
            .clone()
            .ok_or("every key in KILNBASE_JWKS needs a \"kid\"")?;
        let key =
            DecodingKey::from_jwk(jwk).map_err(|e| format!("KILNBASE_JWKS key {kid}: {e}"))?;
        keys.insert(kid, key);
    }
    if keys.is_empty() {
        return Err("KILNBASE_JWKS must contain at least one key".into());
    }

    let port = match get("KILNBASE_PORT") {
        None => 8000,
        Some(p) => p
            .parse()
            .map_err(|_| format!("KILNBASE_PORT is not a valid port: {p}"))?,
    };
    let postgrest_url = get("KILNBASE_POSTGREST_URL")
        .unwrap_or_else(|| "http://postgrest:3000".into())
        .trim_end_matches('/')
        .to_owned();

    Ok(Config {
        port,
        postgrest_url,
        keys,
    })
}

fn required(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<String, String> {
    match get(name) {
        Some(v) if !v.trim().is_empty() && v != PLACEHOLDER => Ok(v),
        _ => Err(format!(
            "{name} is missing or still set to the example value; run `kilnbase init`"
        )),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Throwaway test key pair; never used outside unit tests.
    pub const TEST_JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"_4LWDHrb0SuzG2FzR_-bO1oq5vcB5Gl4e99f6a4Eoxw","y":"lCQcRUMhy-lOOapjF2BjilyefyXSTq79NqcErnHJvZI","kid":"test","alg":"ES256"}]}"#;
    pub const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDqZMOCOe8J0/HFKE
aRFvMSdzxIZIQNSXUEybnOAr2rWhRANCAAT/gtYMetvRK7MbYXNH/5s7Wirm9wHk
aXh731/prgSjHJQkHEVDIcvpTjmqYxdgY4pcnn8l0k6u/TanBK5xyb2S
-----END PRIVATE KEY-----
";

    pub fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn accepts_valid_config() {
        let cfg = load(env(&[("KILNBASE_JWKS", TEST_JWKS)])).unwrap();
        assert_eq!(cfg.port, 8000);
        assert_eq!(cfg.postgrest_url, "http://postgrest:3000");
        assert!(cfg.keys.contains_key("test"));
    }

    #[test]
    fn rejects_missing_placeholder_and_bad_jwks() {
        assert!(load(env(&[])).is_err());
        assert!(load(env(&[("KILNBASE_JWKS", PLACEHOLDER)])).is_err());
        assert!(load(env(&[("KILNBASE_JWKS", r#"{"keys":[]}"#)])).is_err());
        assert!(load(env(&[("KILNBASE_JWKS", "not json")])).is_err());
        let no_kid = TEST_JWKS.replace(r#","kid":"test""#, "");
        assert!(load(env(&[("KILNBASE_JWKS", &no_kid)])).is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(
            load(env(&[
                ("KILNBASE_JWKS", TEST_JWKS),
                ("KILNBASE_PORT", "99999")
            ]))
            .is_err()
        );
    }
}
