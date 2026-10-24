use std::collections::HashMap;

use axum::http::{HeaderMap, StatusCode, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use crate::error::ApiError;

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub role: String,
}

const API_KEY_ROLES: &[&str] = &["anon", "service_role"];
const REQUEST_ROLES: &[&str] = &["anon", "authenticated", "service_role"];

/// Checks the `apikey` header and optional bearer token; returns the token to forward upstream.
pub fn authorize(
    keys: &HashMap<String, DecodingKey>,
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    let api_key = headers
        .get("apikey")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| unauthorized("missing apikey header"))?;
    let api_claims = verify(keys, api_key)?;
    if !API_KEY_ROLES.contains(&api_claims.role.as_str()) {
        return Err(unauthorized("invalid apikey"));
    }

    let Some(auth) = headers.get(header::AUTHORIZATION) else {
        return Ok(api_key.to_owned());
    };
    let token = auth
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| unauthorized("authorization header must be a bearer token"))?;
    let claims = verify(keys, token)?;
    if !REQUEST_ROLES.contains(&claims.role.as_str()) {
        return Err(unauthorized("invalid token"));
    }
    Ok(token.to_owned())
}

fn verify(keys: &HashMap<String, DecodingKey>, token: &str) -> Result<Claims, ApiError> {
    // Algorithm is fixed by us, never taken from the token header.
    let header = decode_header(token).map_err(|_| unauthorized("invalid token"))?;
    let key = header
        .kid
        .as_deref()
        .and_then(|kid| keys.get(kid))
        .ok_or_else(|| unauthorized("invalid token"))?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.leeway = 30;
    decode::<Claims>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(|_| unauthorized("invalid token"))
}

fn unauthorized(message: &'static str) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load, tests::*};
    use axum::http::HeaderValue;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn keys() -> HashMap<String, DecodingKey> {
        load(env(&[("KILNBASE_JWKS", TEST_JWKS)])).unwrap().keys
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn token(role: &str, exp_offset: i64, kid: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.into());
        let claims = json!({ "role": role, "exp": now() as i64 + exp_offset });
        encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn headers(api_key: &str, bearer: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("apikey", HeaderValue::from_str(api_key).unwrap());
        if let Some(b) = bearer {
            h.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {b}")).unwrap(),
            );
        }
        h
    }

    #[test]
    fn anon_key_alone_is_forwarded() {
        let anon = token("anon", 3600, "test");
        assert_eq!(authorize(&keys(), &headers(&anon, None)).unwrap(), anon);
    }

    #[test]
    fn user_token_takes_precedence() {
        let anon = token("anon", 3600, "test");
        let user = token("authenticated", 3600, "test");
        assert_eq!(
            authorize(&keys(), &headers(&anon, Some(&user))).unwrap(),
            user
        );
    }

    #[test]
    fn rejects_missing_expired_unknown_kid_and_bad_roles() {
        let k = keys();
        let anon = token("anon", 3600, "test");
        assert!(authorize(&k, &HeaderMap::new()).is_err());
        assert!(authorize(&k, &headers(&token("anon", -3600, "test"), None)).is_err());
        assert!(authorize(&k, &headers(&token("anon", 3600, "other"), None)).is_err());
        // A user token is not an API key.
        assert!(authorize(&k, &headers(&token("authenticated", 3600, "test"), None)).is_err());
        assert!(authorize(&k, &headers(&anon, Some(&token("postgres", 3600, "test")))).is_err());
        assert!(authorize(&k, &headers(&anon, Some("garbage"))).is_err());
    }

    #[test]
    fn rejects_unsigned_and_tampered_tokens() {
        let k = keys();
        let anon = token("anon", 3600, "test");
        // alg=none with the same claims.
        let none = format!(
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoidGVzdCJ9.{}.",
            anon.split('.').nth(1).unwrap()
        );
        assert!(authorize(&k, &headers(&none, None)).is_err());
        // Signature from one token on another token's payload.
        let parts: Vec<&str> = anon.split('.').collect();
        let other = token("service_role", 3600, "test");
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            other.split('.').nth(1).unwrap(),
            parts[2]
        );
        assert!(authorize(&k, &headers(&forged, None)).is_err());
    }
}
