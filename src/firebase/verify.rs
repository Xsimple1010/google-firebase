use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;

use super::{FirebaseAuth, FirebaseClaims};
use crate::{unix_now, Error, Result};

/// Tolerância de relógio, a mesma que o `jsonwebtoken` usa para `exp`.
const CLOCK_LEEWAY_SECS: u64 = 60;

impl FirebaseAuth {
    /// Valida assinatura, `iss`, `aud`, `exp`, `sub` e `auth_time` de um ID token
    /// e devolve os claims (incluindo seus custom claims `C`, se presentes).
    pub async fn verify_id_token<C: DeserializeOwned + Send + Sync + 'static>(
        &self,
        token: &str,
    ) -> Result<FirebaseClaims<C>> {
        let header = decode_header(token)?;
        let kid = header
            .kid
            .ok_or_else(|| Error::InvalidToken("token sem kid".into()))?;

        let cert_pem = self.certs.get(&kid).await?;
        // from_rsa_pem aceita direto o certificado X.509 PEM do Google.
        let decoding_key = DecodingKey::from_rsa_pem(cert_pem.as_bytes())?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.project_id]);
        validation.set_issuer(&[format!(
            "https://securetoken.google.com/{}",
            self.project_id
        )]);

        let claims = decode::<FirebaseClaims<C>>(token, &decoding_key, &validation)?.claims;

        if claims.sub.trim().is_empty() {
            return Err(Error::InvalidToken("campo 'sub' vazio".into()));
        }
        if claims.auth_time > unix_now() + CLOCK_LEEWAY_SECS {
            return Err(Error::InvalidToken("auth_time no futuro".into()));
        }

        Ok(claims)
    }
}
