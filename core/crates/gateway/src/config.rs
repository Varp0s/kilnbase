use std::collections::HashMap;

use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;

/// Value shipped in `.env.example`; refusing it stops people from running with published secrets.
pub const PLACEHOLDER: &str = "change-me";

pub struct Config {
    pub port: u16,
    pub postgrest_url: String,
    pub auth_url: String,
    pub database_url: String,
    pub storage_dir: std::path::PathBuf,
    pub storage_max_file_size: u64,
    pub storage_signing_key: String,
    pub imgproxy_url: Option<String>,
    pub s3_region: String,
    pub s3_keys: Option<(String, String)>,
    /// `None` means any origin.
    pub cors_origins: Option<Vec<String>>,
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
    let upstream = |name: &str, default: &str| {
        get(name)
            .unwrap_or_else(|| default.into())
            .trim_end_matches('/')
            .to_owned()
    };
    let postgrest_url = upstream("KILNBASE_POSTGREST_URL", "http://postgrest:3000");
    let auth_url = upstream("KILNBASE_AUTH_URL", "http://auth:9999");
    let database_url = required(&get, "KILNBASE_DATABASE_URL")?;
    let storage_signing_key = required(&get, "KILNBASE_STORAGE_SIGNING_KEY")?;
    if storage_signing_key.len() < 32 {
        return Err("KILNBASE_STORAGE_SIGNING_KEY must be at least 32 characters".into());
    }
    let storage_dir = get("KILNBASE_STORAGE_DIR")
        .unwrap_or_else(|| "/data".into())
        .into();
    // Auth is header-based (no cookies), so allowing any origin cannot be used for CSRF.
    let cors_origins = match get("KILNBASE_CORS_ORIGINS").as_deref().map(str::trim) {
        None | Some("") | Some("*") => None,
        Some(list) => Some(
            list.split(',')
                .map(|o| o.trim().trim_end_matches('/').to_owned())
                .filter(|o| !o.is_empty())
                .collect(),
        ),
    };
    let imgproxy_url = get("KILNBASE_IMGPROXY_URL")
        .map(|u| u.trim().trim_end_matches('/').to_owned())
        .filter(|u| !u.is_empty());
    let s3_region = get("KILNBASE_S3_REGION").unwrap_or_else(|| "us-east-1".into());
    // Optional: without a key pair the S3 API still serves users signing with their access token.
    let s3_keys = match (
        get("KILNBASE_S3_ACCESS_KEY_ID").filter(|v| !v.is_empty()),
        get("KILNBASE_S3_SECRET_ACCESS_KEY").filter(|v| !v.is_empty()),
    ) {
        (None, None) => None,
        (Some(id), Some(secret)) if secret.len() >= 32 && secret != PLACEHOLDER => {
            Some((id, secret))
        }
        _ => {
            return Err("KILNBASE_S3_ACCESS_KEY_ID and KILNBASE_S3_SECRET_ACCESS_KEY must be set together, with a secret of at least 32 characters".into());
        }
    };
    let storage_max_file_size = match get("KILNBASE_STORAGE_MAX_FILE_SIZE") {
        None => 50 * 1024 * 1024,
        Some(v) => v
            .parse()
            .map_err(|_| format!("KILNBASE_STORAGE_MAX_FILE_SIZE is not a byte count: {v}"))?,
    };

    Ok(Config {
        port,
        postgrest_url,
        auth_url,
        database_url,
        storage_dir,
        storage_max_file_size,
        storage_signing_key,
        imgproxy_url,
        s3_region,
        s3_keys,
        cors_origins,
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

    /// A complete valid environment with `overrides` applied on top.
    pub fn valid(overrides: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let mut map: HashMap<String, String> = [
            ("KILNBASE_JWKS", TEST_JWKS),
            (
                "KILNBASE_DATABASE_URL",
                "postgres://authenticator:pw@db/postgres",
            ),
            (
                "KILNBASE_STORAGE_SIGNING_KEY",
                "0123456789abcdef0123456789abcdef",
            ),
        ]
        .iter()
        .chain(overrides)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        map.retain(|_, v| !v.is_empty());
        move |k| map.get(k).cloned()
    }

    #[test]
    fn accepts_valid_config() {
        let cfg = load(valid(&[])).unwrap();
        assert_eq!(cfg.port, 8000);
        assert_eq!(cfg.postgrest_url, "http://postgrest:3000");
        assert_eq!(cfg.storage_max_file_size, 50 * 1024 * 1024);
        assert!(cfg.keys.contains_key("test"));
        assert!(cfg.cors_origins.is_none());
        let cfg = load(valid(&[(
            "KILNBASE_CORS_ORIGINS",
            "https://app.example.com/, http://localhost:3000",
        )]))
        .unwrap();
        assert_eq!(
            cfg.cors_origins.unwrap(),
            ["https://app.example.com", "http://localhost:3000"]
        );
    }

    #[test]
    fn rejects_missing_placeholder_and_bad_values() {
        assert!(load(env(&[])).is_err());
        let no_kid = TEST_JWKS.replace(r#","kid":"test""#, "");
        for (k, v) in [
            ("KILNBASE_JWKS", PLACEHOLDER),
            ("KILNBASE_JWKS", r#"{"keys":[]}"#),
            ("KILNBASE_JWKS", "not json"),
            ("KILNBASE_JWKS", no_kid.as_str()),
            ("KILNBASE_DATABASE_URL", ""),
            ("KILNBASE_STORAGE_SIGNING_KEY", PLACEHOLDER),
            ("KILNBASE_STORAGE_SIGNING_KEY", "too-short"),
            ("KILNBASE_STORAGE_MAX_FILE_SIZE", "lots"),
            ("KILNBASE_PORT", "99999"),
            ("KILNBASE_S3_ACCESS_KEY_ID", "only-the-id"),
            (
                "KILNBASE_S3_SECRET_ACCESS_KEY",
                "only-a-secret-that-is-long-enough!!",
            ),
        ] {
            assert!(load(valid(&[(k, v)])).is_err(), "{k}={v}");
        }
    }
}
