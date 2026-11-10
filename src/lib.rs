//! Mini-SDK com só o que o backend usa de Google/Firebase.
//!
//! - [`google`]: autenticação de service account (JWT bearer → access token OAuth2).
//!   Não sabe nada de Firebase; serve para qualquer API do Google.
//! - [`firebase`]: verificação de ID token e custom claims do Firebase Auth.
//!   Usa o módulo `google` para falar com o Identity Toolkit.

pub mod error;
pub mod firebase;
pub mod google;

pub use error::{Error, Result};

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
