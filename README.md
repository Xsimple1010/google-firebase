# google-firebase

```
src/
├── google/            # Google puro (serve p/ qualquer API do Google)
│   ├── service_account.rs   ServiceAccountKey (from_json / from_file)
│   └── oauth.rs             ServiceAccountAuth: JWT bearer -> access token (cacheado)
└── firebase/          # Firebase Auth (usa google/ por baixo)
    ├── claims.rs            FirebaseClaims<C>, FirebaseInfo
    ├── certs.rs             cache dos certificados X.509 (respeita Cache-Control)
    ├── verify.rs            FirebaseAuth::verify_id_token::<C>()
    └── admin.rs             FirebaseAuth::set_custom_claims()
```

## Uso

```rust
// env: FIREBASE_PROJECT_ID + FIREBASE_SERVICE_ACCOUNT_FILE (ou _JSON)
let auth = FirebaseAuth::from_env()?;                       // crie UMA vez

let claims: FirebaseClaims<ActorClaims> = auth.verify_id_token(token).await?;
auth.set_custom_claims(&claims.user_id, &ActorClaims::Customer { id }).await?;
```
