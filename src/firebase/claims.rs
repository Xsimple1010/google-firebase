use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Bloco `firebase` do ID token.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FirebaseInfo {
    /// `password`, `google.com`, `phone`, `anonymous`, ...
    pub sign_in_provider: String,
    /// Chaves dinâmicas por provider, ex.: `{"google.com": ["123"], "email": ["a@b.com"]}`.
    #[serde(default)]
    pub identities: HashMap<String, Vec<String>>,
    pub tenant: Option<String>,
}

/// Claims de um ID token do Firebase.
///
/// `C` é o tipo dos seus custom claims (ex.: seu enum `ActorClaims`). O Firebase
/// mescla os `customAttributes` direto na RAIZ do token, por isso o
/// `#[serde(flatten)]`: sem ele os claims customizados seriam ignorados em silêncio.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FirebaseClaims<C = ()> {
    pub sub: String,
    pub user_id: String,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub auth_time: u64,
    pub firebase: FirebaseInfo,

    // Ausentes dependendo do provider (telefone, anônimo, ...).
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub picture: Option<String>,

    #[serde(flatten)]
    pub custom: Option<C>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Deserialize, Serialize)]
    enum Actor {
        Store { id: String },
        Customer { id: String },
    }

    const BASE: &str = r#""sub":"u1","user_id":"u1","iss":"i","aud":"a","iat":1,"exp":2,"auth_time":1"#;

    #[test]
    fn flattens_custom_claims_from_token_root() {
        let json = format!(
            r#"{{{BASE},"email":"a@b.com","firebase":{{"sign_in_provider":"password","identities":{{"email":["a@b.com"]}}}},"Store":{{"id":"s1"}}}}"#
        );
        let c: FirebaseClaims<Actor> = serde_json::from_str(&json).unwrap();
        assert!(matches!(c.custom, Some(Actor::Store { .. })));
    }

    #[test]
    fn custom_is_none_before_bootstrap() {
        let json = format!(r#"{{{BASE},"firebase":{{"sign_in_provider":"password"}}}}"#);
        let c: FirebaseClaims<Actor> = serde_json::from_str(&json).unwrap();
        assert!(c.custom.is_none());
        assert!(c.email.is_none()); // email é opcional (telefone/anônimo)
    }

    #[test]
    fn parses_google_identities() {
        let json = format!(
            r#"{{{BASE},"firebase":{{"sign_in_provider":"google.com","identities":{{"google.com":["123"],"email":["a@b.com"]}}}}}}"#
        );
        let c: FirebaseClaims<Actor> = serde_json::from_str(&json).unwrap();
        assert_eq!(c.firebase.sign_in_provider, "google.com");
        assert_eq!(c.firebase.identities["google.com"], vec!["123"]);
    }
}
