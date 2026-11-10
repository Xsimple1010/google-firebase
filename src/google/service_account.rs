use std::{fmt, path::Path};

use serde::Deserialize;

use crate::{Error, Result};

/// Campos relevantes do JSON de service account baixado do console.
#[derive(Clone, Deserialize)]
pub struct ServiceAccountKey {
    pub client_email: String,
    pub private_key: String,
    pub token_uri: String,
    pub project_id: Option<String>,
}

// Debug manual: nunca imprimir a chave privada em logs.
impl fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("private_key", &"<redacted>")
            .field("token_uri", &self.token_uri)
            .field("project_id", &self.project_id)
            .finish()
    }
}

impl ServiceAccountKey {
    pub fn from_json(raw: &str) -> Result<Self> {
        serde_json::from_str(raw)
            .map_err(|e| Error::ServiceAccount(format!("JSON inválido: {e}")))
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|e| {
            Error::ServiceAccount(format!("erro ao ler '{}': {e}", path.display()))
        })?;
        Self::from_json(&raw)
    }
}
