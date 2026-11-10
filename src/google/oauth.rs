use std::time::{Duration, Instant};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::{ensure_success, ServiceAccountKey};
use crate::{unix_now, Result};

const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Renova um pouco antes de expirar, para nunca entregar um token quase vencido.
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

struct CachedToken {
    value: String,
    expires_at: Instant,
}

/// Obtém (e cacheia) access tokens OAuth2 de uma service account para um escopo.
pub struct ServiceAccountAuth {
    key: ServiceAccountKey,
    scope: String,
    http: Client,
    cached: Mutex<Option<CachedToken>>,
}

impl ServiceAccountAuth {
    pub fn new(key: ServiceAccountKey, scope: impl Into<String>, http: Client) -> Self {
        Self {
            key,
            scope: scope.into(),
            http,
            cached: Mutex::new(None),
        }
    }

    /// Retorna um access token válido, reaproveitando o anterior enquanto der.
    pub async fn access_token(&self) -> Result<String> {
        // O lock fica preso durante a renovação: chamadas concorrentes esperam
        // e reaproveitam o token novo em vez de dispararem N requests ao Google.
        let mut guard = self.cached.lock().await;

        if let Some(c) = guard.as_ref() {
            if c.expires_at > Instant::now() + REFRESH_MARGIN {
                return Ok(c.value.clone());
            }
        }

        let fresh = self.request_token().await?;
        let value = fresh.value.clone();
        *guard = Some(fresh);
        Ok(value)
    }

    async fn request_token(&self) -> Result<CachedToken> {
        let now = unix_now();
        let claims = AssertionClaims {
            iss: &self.key.client_email,
            scope: &self.scope,
            aud: &self.key.token_uri,
            iat: now,
            exp: now + 3600,
        };

        let encoding_key = EncodingKey::from_rsa_pem(self.key.private_key.as_bytes())?;
        let assertion = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)?;

        let resp = self
            .http
            .post(&self.key.token_uri)
            .form(&[
                ("grant_type", JWT_BEARER_GRANT),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await?;

        let body: TokenResponse = ensure_success(resp).await?.json().await?;

        Ok(CachedToken {
            value: body.access_token,
            expires_at: Instant::now() + Duration::from_secs(body.expires_in),
        })
    }
}
