//! Teste ponta a ponta SEM navegador nem app: usa a REST API pública do Firebase Auth
//! para logar com email/senha e pegar um ID token real.
//!
//! FIREBASE_PROJECT_ID=meu-projeto \
//! FIREBASE_SERVICE_ACCOUNT_FILE=./firebase.json \
//! FIREBASE_WEB_API_KEY=AIza... \
//! TEST_EMAIL=teste@exemplo.com TEST_PASSWORD=senha-forte-123 \
//! cargo run --example e2e

use google_firebase::firebase::{FirebaseAuth, FirebaseClaims};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
enum Actor {
    Store { id: String },
    Customer { id: String },
}

#[derive(Deserialize)]
struct SignInResponse {
    #[serde(rename = "idToken")]
    id_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
}

#[derive(Deserialize)]
struct RefreshResponse {
    id_token: String,
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("defina a variável {name}"))
}

/// Tenta logar; se o usuário de teste ainda não existe, cria.
async fn sign_in(http: &reqwest::Client, api_key: &str, email: &str, password: &str) -> SignInResponse {
    let body = json!({ "email": email, "password": password, "returnSecureToken": true });
    for method in ["signInWithPassword", "signUp"] {
        let resp = http
            .post(format!("https://identitytoolkit.googleapis.com/v1/accounts:{method}"))
            .query(&[("key", api_key)])
            .json(&body)
            .send()
            .await
            .expect("falha de rede");
        if resp.status().is_success() {
            return resp.json().await.expect("resposta inesperada");
        }
    }
    panic!("não consegui logar nem criar o usuário de teste (provider Email/Password habilitado?)");
}


#[tokio::test]
async fn verify_end_set_store_attribute() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let api_key = env("FIREBASE_WEB_API_KEY");
    let http = reqwest::Client::new();
    let auth = FirebaseAuth::from_env()?;

    // 1) ID token real, sem navegador
    let session = sign_in(&http, &api_key, &env("TEST_EMAIL"), &env("TEST_PASSWORD")).await;

    // 2) valida assinatura/iss/aud/exp
    let claims: FirebaseClaims<Actor> = auth.verify_id_token(&session.id_token).await?;
    println!(
        "1) token verificado: uid={} provider={} custom={:?}",
        claims.user_id, claims.firebase.sign_in_provider, claims.custom
    );

    // 3) grava custom claims
    auth.set_custom_claims(&claims.user_id, &Actor::Store { id: "tests-123".into() })
        .await?;
    println!("2) custom claims gravados");

    // 4) claims só aparecem em tokens novos: força refresh, como getIdToken(true)
    let refreshed: RefreshResponse = http
        .post("https://securetoken.googleapis.com/v1/token")
        .query(&[("key", &api_key)])
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", session.refresh_token.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let after: FirebaseClaims<Actor> = auth.verify_id_token(&refreshed.id_token).await?;
    match after.custom {
        Some(Actor::Store { ref id }) if id == "tests-123" => {
            println!("3) OK: claim Store{{id: {id}}} presente no token renovado");
            println!("\nToken para testar o GraphQL:\n{}", refreshed.id_token);
            Ok(())
        }
        other => Err(format!("claim não apareceu no token renovado: {other:?}").into()),
    }
}
