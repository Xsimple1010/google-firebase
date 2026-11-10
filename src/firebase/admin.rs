use serde::Serialize;

use super::FirebaseAuth;
use crate::{google::ensure_success, Error, Result};

const ACCOUNTS_UPDATE_URL: &str = "https://identitytoolkit.googleapis.com/v1/accounts:update";
/// Limite do Firebase para `customAttributes`.
const MAX_CUSTOM_CLAIMS_BYTES: usize = 1000;

impl FirebaseAuth {
    /// Define os custom claims do usuário `uid` (substitui os anteriores).
    ///
    /// Só aparecem em ID tokens emitidos DEPOIS desta chamada: o client precisa
    /// forçar refresh (`getIdToken(true)` no Flutter).
    pub async fn set_custom_claims<C: Serialize>(&self, uid: &str, claims: &C) -> Result<()> {
        let custom_attributes = serde_json::to_string(claims)?;
        if custom_attributes.len() > MAX_CUSTOM_CLAIMS_BYTES {
            return Err(Error::ClaimsTooLarge(custom_attributes.len()));
        }

        let access_token = self.admin.access_token().await?;

        let resp = self
            .http
            .post(ACCOUNTS_UPDATE_URL)
            .bearer_auth(access_token)
            .json(&serde_json::json!({
                "localId": uid,
                "customAttributes": custom_attributes,
            }))
            .send()
            .await?;

        ensure_success(resp).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{firebase::FirebaseAuth, google::ServiceAccountKey, Error};

    #[tokio::test]
    async fn rejects_oversized_claims_before_any_network_call() {
        let key = ServiceAccountKey::from_json(
            r#"{"client_email":"x@y","private_key":"k","token_uri":"http://invalid"}"#,
        )
        .unwrap();
        let auth = FirebaseAuth::new("proj", key);

        let big = serde_json::json!({ "data": "x".repeat(1200) });
        let err = auth.set_custom_claims("uid", &big).await.unwrap_err();
        assert!(matches!(err, Error::ClaimsTooLarge(_)));
    }
}
