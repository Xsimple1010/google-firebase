//! Parte "Firebase Auth": verificação de ID token e custom claims.
//! Usa o módulo [`crate::google`] só para obter o access token da service account.

mod admin;
mod certs;
mod claims;
mod verify;

pub use claims::{FirebaseClaims, FirebaseInfo};

use reqwest::Client;

use crate::{
    google::{ServiceAccountAuth, ServiceAccountKey},
    Error, Result,
};
use certs::CertCache;

const IDENTITY_TOOLKIT_SCOPE: &str = "https://www.googleapis.com/auth/identitytoolkit";

/// Cliente do Firebase Auth. Crie UMA vez e reaproveite (cacheia certificados e
/// access token internamente).
pub struct FirebaseAuth {
    project_id: String,
    http: Client,
    certs: CertCache,
    admin: ServiceAccountAuth,
}

impl FirebaseAuth {
    pub fn new(project_id: impl Into<String>, key: ServiceAccountKey) -> Self {
        let http = Client::new(); // Client é um Arc por dentro: clonar é barato
        Self {
            project_id: project_id.into(),
            certs: CertCache::new(http.clone()),
            admin: ServiceAccountAuth::new(key, IDENTITY_TOOLKIT_SCOPE, http.clone()),
            http,
        }
    }

    /// Lê `FIREBASE_PROJECT_ID` e a service account de
    /// `FIREBASE_SERVICE_ACCOUNT_FILE` (caminho) ou, se ausente,
    /// `FIREBASE_SERVICE_ACCOUNT_JSON` (conteúdo inline).
    pub fn from_env() -> Result<Self> {
        let project_id = std::env::var("FIREBASE_PROJECT_ID")
            .map_err(|_| Error::MissingConfig("FIREBASE_PROJECT_ID"))?;

        let key = if let Ok(path) = std::env::var("FIREBASE_SERVICE_ACCOUNT_FILE") {
            ServiceAccountKey::from_file(path)?
        } else if let Ok(raw) = std::env::var("FIREBASE_SERVICE_ACCOUNT_JSON") {
            ServiceAccountKey::from_json(&raw)?
        } else {
            return Err(Error::MissingConfig(
                "FIREBASE_SERVICE_ACCOUNT_FILE ou FIREBASE_SERVICE_ACCOUNT_JSON",
            ));
        };

        Ok(Self::new(project_id, key))
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }
}
