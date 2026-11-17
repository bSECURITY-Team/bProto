//! Durable single-target reconciliation through the existing configuration agent.
//! A successful HTTP request is insufficient: acknowledge the exact revision.
use crate::{ApiError, App, now};
use axum::{Json, extract::State};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

pub(crate) struct Worker {
    inbound: i64,
    endpoint: String,
    client: reqwest::Client,
}

impl Worker {
    pub(crate) fn from_env() -> anyhow::Result<Option<Self>> {
        let inbound = match std::env::var("BPROTO_KEY_SYNC_INBOUND") {
            Ok(value) => value.parse::<i64>()?,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(_) => anyhow::bail!("invalid key sync configuration"),
        };
        anyhow::ensure!(inbound > 0, "invalid inbound id");
        let endpoint = std::env::var("BPROTO_KEY_SYNC_AGENT_URL")?;
        let url =
            url::Url::parse(&endpoint).map_err(|_| anyhow::anyhow!("invalid key agent URL"))?;
        anyhow::ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "key agent requires fixed HTTPS origin"
        );
        let identity = std::fs::read(std::env::var("BPROTO_CONFIG_AGENT_IDENTITY")?)?;
        let ca = std::fs::read(std::env::var("BPROTO_CONFIG_AGENT_CA")?)?;
        let client = reqwest::Client::builder()
            .identity(reqwest::Identity::from_pem(&identity)?)
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(95))
            .build()?;
        Ok(Some(Self {
            inbound,
            endpoint,
            client,
        }))
    }

    pub(crate) async fn run(self, app: App) {
        loop {
            if self.once(&app).await.is_err() {
                // Never retain reqwest errors: they may contain the endpoint.
                let _ = sqlx::query("UPDATE key_sync SET status = 'pending', last_error = 'Agent reconciliation failed' WHERE id = 1")
                    .execute(&app.db).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    async fn once(&self, app: &App) -> anyhow::Result<()> {
        let (revision, document) = snapshot(app, self.inbound).await?;
        let state: i64 = sqlx::query_scalar("SELECT applied_revision FROM key_sync WHERE id = 1")
            .fetch_one(&app.db)
            .await?;
        // Always retry the desired revision. Agent's idempotent path also checks
        // runtime health, detecting server restart/drift without rotating keys.
        let mut response = self
            .client
            .post(format!(
                "{}users/apply",
                self.endpoint.trim_end_matches('/').to_owned() + "/"
            ))
            .header("Content-Type", "application/json")
            .body(document.to_string())
            .send()
            .await?;
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(body.len() + chunk.len() <= 4096, "agent response too large");
            body.extend_from_slice(&chunk);
        }
        let receipt: Value = serde_json::from_slice(&body)?;
        let outcome = receipt
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("invalid");
        if !status.is_success()
            || outcome != "applied"
            || receipt["revision"].as_i64() != Some(revision)
        {
            let safe = match outcome {
                "rolled_back" => "rolled_back",
                "rollback_failed" => "rollback_failed",
                _ => "pending",
            };
            sqlx::query("UPDATE key_sync SET status = ?, last_error = 'Agent did not confirm desired revision', updated_at = ? WHERE id = 1")
                .bind(safe).bind(now()).execute(&app.db).await?;
            return Ok(());
        }
        anyhow::ensure!(revision >= state, "applied revision regressed");
        sqlx::query("UPDATE key_sync SET applied_revision = ?, status = CASE WHEN desired_revision = ? THEN 'applied' ELSE 'pending' END, last_error = NULL, updated_at = ? WHERE id = 1")
            .bind(revision).bind(revision).bind(now()).execute(&app.db).await?;
        Ok(())
    }
}

fn proof(key: &[u8; 32], domain: &[u8], value: &Value) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key length");
    mac.update(domain);
    mac.update(value.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub(crate) async fn snapshot(app: &App, inbound: i64) -> anyhow::Result<(i64, Value)> {
    let mut tx = app.db.begin().await?;
    // Acquire SQLite's writer lock before reads; no deferred-read upgrade race.
    sqlx::query("UPDATE key_sync SET id = id WHERE id = 1")
        .execute(&mut *tx)
        .await?;
    let rows = sqlx::query("SELECT u.id, k.psk FROM users u JOIN keys k ON k.user_id = u.id JOIN inbounds i ON i.id = u.inbound_id \
        WHERE u.is_admin = 0 AND u.inbound_id = ? AND u.status = 'active' AND i.status = 'active' AND k.status = 'active' \
        AND (u.expires_at IS NULL OR u.expires_at > ?) AND (u.traffic_limit_bytes IS NULL OR u.traffic_used_bytes < u.traffic_limit_bytes) \
        ORDER BY u.id, k.id").bind(inbound).bind(now()).fetch_all(&mut *tx).await?;
    let mut users = Vec::new();
    for row in rows {
        let psk: Vec<u8> = row.get("psk");
        anyhow::ensure!(psk.len() == 32, "invalid stored credential");
        users.push(json!({"id": row.get::<i64, _>("id"), "psk": hex::encode(psk)}));
    }
    let owned_users: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM users WHERE is_admin = 0 AND inbound_id = ? ORDER BY id",
    )
    .bind(inbound)
    .fetch_all(&mut *tx)
    .await?;
    let revocations =
        sqlx::query("SELECT user_id, psk FROM key_sync_revocations ORDER BY user_id, psk")
            .fetch_all(&mut *tx)
            .await?;
    let mut revoked = Vec::new();
    for row in revocations {
        let uid: i64 = row.get("user_id");
        let psk: Vec<u8> = row.get("psk");
        revoked.push(hex::encode(Sha256::digest(
            format!("{uid}:{}", hex::encode(psk)).as_bytes(),
        )));
    }
    let hash = proof(
        &app.tag_key,
        b"bproto desired users v1\0",
        &json!({"inbound_id": inbound, "users": users, "owned_users": owned_users, "revoked": revoked}),
    );
    // This also detects time-based expiry without a DB mutation.
    sqlx::query("UPDATE key_sync SET desired_revision = desired_revision + 1, desired_hash = ?, status = 'pending' WHERE id = 1 AND (desired_hash IS NULL OR desired_hash != ?)")
        .bind(&hash).bind(&hash).execute(&mut *tx).await?;
    let revision: i64 = sqlx::query_scalar("SELECT desired_revision FROM key_sync WHERE id = 1")
        .fetch_one(&mut *tx)
        .await?;
    let mut document = json!({"version": 2, "revision": revision, "inbound_id": inbound, "users": users, "owned_users": owned_users, "revoked": revoked});
    let signature = proof(&app.tag_key, b"bproto users snapshot v1\0", &document);
    document["tag_proof"] = json!(signature);
    tx.commit().await?;
    Ok((revision, document))
}

pub(crate) async fn status(State(app): State<App>) -> Result<Json<Value>, ApiError> {
    let row = sqlx::query("SELECT desired_revision, applied_revision, status, last_error, updated_at FROM key_sync WHERE id = 1")
        .fetch_one(&app.db).await?;
    Ok(Json(
        json!({"desired_revision": row.get::<i64, _>("desired_revision"),
        "applied_revision": row.get::<i64, _>("applied_revision"),
        "status": row.get::<String, _>("status"), "last_error": row.get::<Option<String>, _>("last_error"),
        "updated_at": row.get::<Option<i64>, _>("updated_at"),
        "configured": std::env::var_os("BPROTO_KEY_SYNC_INBOUND").is_some(),
        "inbound_id": std::env::var("BPROTO_KEY_SYNC_INBOUND").ok().and_then(|s| s.parse::<i64>().ok())}),
    ))
}
