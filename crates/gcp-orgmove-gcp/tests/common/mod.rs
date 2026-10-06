#![allow(dead_code)]
use gcp_orgmove_gcp::real::{Config, RealGcp};
use serde_json::{json, Value};
use wiremock::MockServer;

pub async fn server() -> (MockServer, RealGcp) {
    let server = MockServer::start().await;
    let creds = google_cloud_auth::credentials::anonymous::Builder::new().build();
    let mut cfg = Config::single(creds, 4, Some(server.uri()));
    cfg.identity_backoff = gcp_orgmove_gcp::identity::Backoff {
        attempts: 3,
        initial: std::time::Duration::from_millis(1),
        max: std::time::Duration::from_millis(2),
    };
    let gcp = RealGcp::new(cfg);
    (server, gcp)
}

pub fn project_json(id: &str, number: &str, parent: &str) -> Value {
    json!({
        "name": format!("projects/{number}"),
        "parent": parent,
        "projectId": id,
        "state": "ACTIVE",
        "displayName": id,
        "etag": "W/\"abc\"",
        "labels": {"env": "prod"}
    })
}
