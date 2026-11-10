pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuração ausente: {0}")]
    MissingConfig(&'static str),

    #[error("service account inválida: {0}")]
    ServiceAccount(String),

    #[error("falha de rede: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Google respondeu {status}: {body}")]
    GoogleApi { status: u16, body: String },

    #[error("erro de JWT: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("token inválido: {0}")]
    InvalidToken(String),

    #[error("custom claims excedem 1000 bytes ({0} bytes)")]
    ClaimsTooLarge(usize),

    #[error("erro de JSON: {0}")]
    Json(#[from] serde_json::Error),
}
