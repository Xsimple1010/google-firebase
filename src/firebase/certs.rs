use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use reqwest::{header::CACHE_CONTROL, Client};
use tokio::sync::RwLock;

use crate::{google::ensure_success, Error, Result};

const CERTS_URL: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const DEFAULT_TTL: Duration = Duration::from_secs(3600);
/// Um `kid` desconhecido só força novo download se o último foi há mais que isso,
/// evitando que tokens forjados com `kid` aleatório gerem um request ao Google por chamada.
const MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

struct Cached {
    certs: HashMap<String, String>,
    fetched_at: Instant,
    expires_at: Instant,
}

/// Cache dos certificados X.509 públicos usados pelo Firebase para assinar ID tokens.
/// Respeita o `Cache-Control: max-age` da resposta do Google (rotação a cada ~6h).
pub(crate) struct CertCache {
    http: Client,
    inner: RwLock<Option<Cached>>,
}

impl CertCache {
    pub(crate) fn new(http: Client) -> Self {
        Self {
            http,
            inner: RwLock::new(None),
        }
    }

    /// Retorna o certificado PEM para o `kid`, baixando/renovando se preciso.
    pub(crate) async fn get(&self, kid: &str) -> Result<String> {
        let must_refresh = {
            let guard = self.inner.read().await;
            match guard.as_ref() {
                None => true,
                Some(c) => {
                    let now = Instant::now();
                    c.expires_at <= now
                        || (!c.certs.contains_key(kid)
                            && c.fetched_at + MIN_REFETCH_INTERVAL <= now)
                }
            }
        };

        if must_refresh {
            self.refresh().await?;
        }

        let guard = self.inner.read().await;
        guard
            .as_ref()
            .and_then(|c| c.certs.get(kid).cloned())
            .ok_or_else(|| Error::InvalidToken(format!("certificado não encontrado para kid {kid}")))
    }

    async fn refresh(&self) -> Result<()> {
        let resp = ensure_success(self.http.get(CERTS_URL).send().await?).await?;

        let ttl = resp
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_max_age)
            .unwrap_or(DEFAULT_TTL);

        let certs: HashMap<String, String> = resp.json().await?;
        let now = Instant::now();

        *self.inner.write().await = Some(Cached {
            certs,
            fetched_at: now,
            expires_at: now + ttl,
        });
        Ok(())
    }
}

fn parse_max_age(header: &str) -> Option<Duration> {
    header
        .split(',')
        .find_map(|d| d.trim().strip_prefix("max-age=")?.parse::<u64>().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_max_age() {
        assert_eq!(
            parse_max_age("public, max-age=19345, must-revalidate"),
            Some(Duration::from_secs(19345))
        );
        assert_eq!(parse_max_age("no-store"), None);
    }
}
