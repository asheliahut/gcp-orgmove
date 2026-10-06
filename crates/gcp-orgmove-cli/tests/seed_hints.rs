//! A manifest (or `init` flags) tells the router who owns what, so the first
//! call goes to the right login instead of being refused first.

use clap::Parser;
use gcp_orgmove_cli::cli::Cli;
use gcp_orgmove_cli::login::seed_hints;
use gcp_orgmove_core::{Gcp, Resource};
use gcp_orgmove_gcp::auth::static_token_credentials;
use gcp_orgmove_gcp::real::{Config, RealGcp, Side, SideConfig};
use serde_json::json;
use wiremock::matchers::{any, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn locked() -> MockServer {
    let s = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(403).set_body_json(
            json!({"error": {"code": 403, "message": "no", "status": "PERMISSION_DENIED"}}),
        ))
        .with_priority(10)
        .mount(&s)
        .await;
    s
}

async fn setup() -> (MockServer, MockServer, RealGcp) {
    let (src, dst) = (locked().await, locked().await);
    let gcp = RealGcp::new(Config {
        source: SideConfig {
            credentials: static_token_credentials("s", None),
            endpoint: Some(src.uri()),
        },
        destination: Some(SideConfig {
            credentials: static_token_credentials("d", None),
            endpoint: Some(dst.uri()),
        }),
        move_side: Side::Source,
        concurrency: 2,
        identity_backoff: Default::default(),
    });
    (src, dst, gcp)
}

async fn count(s: &MockServer, needle: &str) -> usize {
    s.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().contains(needle))
        .count()
}

fn command(args: &[&str]) -> gcp_orgmove_cli::cli::Command {
    let mut argv = vec!["gcp-orgmove"];
    argv.extend_from_slice(args);
    Cli::try_parse_from(argv).unwrap().command
}

#[tokio::test]
async fn a_manifest_seeds_org_and_folder_owners() {
    let (src, dst, gcp) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("orgmove.yaml");
    std::fs::write(
        &manifest,
        "version: 1\nsource_org: \"111\"\ndestination_org: \"222\"\ndefault_destination_folder: \"20\"\nselection:\n  source_folders: [\"10\"]\n",
    )
    .unwrap();
    seed_hints(&gcp, &command(&["status"]), &manifest);

    Mock::given(method("GET"))
        .and(path("/v3/folders/20"))
        .and(header("authorization", "Bearer d"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"name": "folders/20", "parent": "organizations/222", "state": "ACTIVE"}),
        ))
        .mount(&dst)
        .await;
    Mock::given(method("GET"))
        .and(path("/v3/folders/10"))
        .and(header("authorization", "Bearer s"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"name": "folders/10", "parent": "organizations/111", "state": "ACTIVE"}),
        ))
        .mount(&src)
        .await;

    gcp.get_folder_ancestry(&"20".parse().unwrap())
        .await
        .unwrap();
    gcp.get_folder_ancestry(&"10".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        count(&src, "folders/20").await,
        0,
        "destination folder went straight to the destination login"
    );
    assert_eq!(
        count(&dst, "folders/10").await,
        0,
        "source folder went straight to the source login"
    );
}

#[tokio::test]
async fn init_flags_seed_the_org_owners_before_any_manifest_exists() {
    let (src, dst, gcp) = setup().await;
    seed_hints(
        &gcp,
        &command(&["init", "--source-org", "111", "--destination-org", "222"]),
        std::path::Path::new("/does/not/exist.yaml"),
    );
    Mock::given(method("POST"))
        .and(path("/v3/organizations/222:testIamPermissions"))
        .and(header("authorization", "Bearer d"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"permissions": ["resourcemanager.organizations.get"]})),
        )
        .mount(&dst)
        .await;
    let got = gcp
        .test_permissions(
            &Resource::Org("222".parse().unwrap()),
            &["resourcemanager.organizations.get".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(count(&src, "organizations/222").await, 0);
}

#[tokio::test]
async fn a_missing_or_broken_manifest_just_means_routing_learns_as_it_goes() {
    let (_src, dst, gcp) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "version: [not a manifest").unwrap();
    seed_hints(&gcp, &command(&["status"]), &bad);
    seed_hints(&gcp, &command(&["status"]), &dir.path().join("absent.yaml"));
    Mock::given(method("GET"))
        .and(path("/v3/folders/20"))
        .and(header("authorization", "Bearer d"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"name": "folders/20", "parent": "organizations/222", "state": "ACTIVE"}),
        ))
        .mount(&dst)
        .await;
    // still works, via the refuse-then-fall-back path
    gcp.get_folder_ancestry(&"20".parse().unwrap())
        .await
        .unwrap();
}
