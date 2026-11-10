//! Substitui o token.rs antigo: toda a lógica de Google/Firebase agora vive no
//! crate `google-firebase`; aqui sobra só a cola com o Axum e com o seu erro.
//!
//! Em err.rs (ou aqui) adicione a conversão do erro do SDK:
//!     impl From<google_firebase::Error> for AstraAuthError { ... }
//! Seus ActorClaims continuam no app (firebase_claims.rs); só ServiceAccountKey,
//! GoogleAuthClaims, GoogleTokenResponse, FirebaseClaims e FirebaseInfo saem de lá.

use std::sync::LazyLock;

use axum::{extract::FromRequestParts, http::request::Parts};
use google_firebase::firebase::{FirebaseAuth, FirebaseClaims};
use reqwest::header::AUTHORIZATION;

use crate::{err::AstraAuthError, firebase_claims::ActorClaims};

pub type AppClaims = FirebaseClaims<ActorClaims>;

/// Criado uma vez: cacheia certificados do Firebase e o access token da service account.
static FIREBASE: LazyLock<FirebaseAuth> =
    LazyLock::new(|| FirebaseAuth::from_env().expect("Firebase mal configurado"));

impl From<google_firebase::Error> for AstraAuthError {
    fn from(e: google_firebase::Error) -> Self {
        AstraAuthError::Validation(e.to_string())
    }
}

pub struct Token;

impl Token {
    pub async fn set_custom_attributes(
        claims: &AppClaims,
        actor: ActorClaims,
    ) -> Result<(), AstraAuthError> {
        Ok(FIREBASE.set_custom_claims(&claims.user_id, &actor).await?)
    }

    pub async fn validade_as_firebase(token: &str) -> Result<AppClaims, AstraAuthError> {
        Ok(FIREBASE.verify_id_token(token).await?)
    }
}

pub struct BearerToken(pub Option<AppClaims>);

impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = String;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let Some(token) = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return Ok(BearerToken(None));
        };

        match Token::validade_as_firebase(token).await {
            Ok(claims) => Ok(BearerToken(Some(claims))),
            Err(e) => {
                eprintln!("Erro ao validar token: {e:?}");
                Ok(BearerToken(None))
            }
        }
    }
}
