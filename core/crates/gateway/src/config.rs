/// Value shipped in `.env.example`; refusing it stops people from running with published secrets.
pub const PLACEHOLDER: &str = "change-me";

#[derive(Debug)]
pub struct Config {
    pub port: u16,
    pub jwks: serde_json::Value,
}

/// Reads config through `get` so tests don't have to mutate the process environment.
pub fn load(get: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
    let jwks_raw = required(&get, "KILNBASE_JWKS")?;
    let jwks: serde_json::Value = serde_json::from_str(&jwks_raw)
        .map_err(|e| format!("KILNBASE_JWKS is not valid JSON: {e}"))?;
    let has_keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .is_some_and(|k| !k.is_empty());
    if !has_keys {
        return Err("KILNBASE_JWKS must contain a non-empty \"keys\" array".into());
    }

    let port = match get("KILNBASE_PORT") {
        None => 8000,
        Some(p) => p
            .parse()
            .map_err(|_| format!("KILNBASE_PORT is not a valid port: {p}"))?,
    };

    Ok(Config { port, jwks })
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
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    const JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b"}]}"#;

    #[test]
    fn accepts_valid_config() {
        let cfg = load(env(&[("KILNBASE_JWKS", JWKS)])).unwrap();
        assert_eq!(cfg.port, 8000);
    }

    #[test]
    fn rejects_missing_placeholder_and_empty_jwks() {
        assert!(load(env(&[])).is_err());
        assert!(load(env(&[("KILNBASE_JWKS", PLACEHOLDER)])).is_err());
        assert!(load(env(&[("KILNBASE_JWKS", r#"{"keys":[]}"#)])).is_err());
        assert!(load(env(&[("KILNBASE_JWKS", "not json")])).is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(load(env(&[("KILNBASE_JWKS", JWKS), ("KILNBASE_PORT", "99999")])).is_err());
    }
}
