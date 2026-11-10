//! Parte "Google puro": service account + OAuth2. Nada aqui é específico do Firebase.

mod oauth;
mod service_account;

pub use oauth::ServiceAccountAuth;
pub use service_account::ServiceAccountKey;

use crate::{Error, Result};

/// Converte respostas não-2xx em [`Error::GoogleApi`] (com o corpo, que costuma
/// explicar o motivo), em vez de falhar depois com um erro confuso de parse.
pub(crate) async fn ensure_success(resp: reqwest::Response) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    Err(Error::GoogleApi {
        status: status.as_u16(),
        body,
    })
}
