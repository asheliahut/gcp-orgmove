//! Two logins: each mock server accepts only its own bearer token and answers
//! 403 to anything else, like an org the other login can't see.

mod common;

use common::project_json;
use gcp_orgmove_core::*;
use gcp_orgmove_gcp::auth::static_token_credentials;
use gcp_orgmove_gcp::real::{Config, RealGcp, Side, SideConfig};
use serde_json::json;
use wiremock::matchers::{any, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SRC_TOKEN: &str = "src-token";
const DST_TOKEN: &str = "dst-token";
const EXPORT: &str = "constraints/resourcemanager.allowedExportDestinations";
const IMPORT: &str = "constraints/resourcemanager.allowedImportSources";

fn forbidden() -> ResponseTemplate {
    ResponseTemplate::new(403).set_body_json(json!({"error": {"code": 403, "message": "caller lacks permission", "status": "PERMISSION_DENIED"}}))
}
fn missing() -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_json(
        json!({"error": {"code": 404, "message": "not found", "status": "NOT_FOUND"}}),
    )
}

/// A server that 403s everything unless a more specific mock (with the right token) matches.
async fn locked_server() -> MockServer {
    let s = MockServer::start().await;
    Mock::given(any())
        .respond_with(forbidden())
        .with_priority(10)
        .mount(&s)
        .await;
    s
}

struct Split {
    src: MockServer,
    dst: MockServer,
    gcp: RealGcp,
}

async fn split_with(move_side: Side) -> Split {
    let (src, dst) = (locked_server().await, locked_server().await);
    let cfg = Config {
        source: SideConfig {
            credentials: static_token_credentials(SRC_TOKEN, Some("src-quota")),
            endpoint: Some(src.uri()),
        },
        destination: Some(SideConfig {
            credentials: static_token_credentials(DST_TOKEN, Some("dst-quota")),
            endpoint: Some(dst.uri()),
        }),
        move_side,
        concurrency: 4,
        identity_backoff: Default::default(),
    };
    Split {
        gcp: RealGcp::new(cfg),
        src,
        dst,
    }
}

async fn split() -> Split {
    split_with(Side::Source).await
}

fn bearer(t: &str) -> wiremock::matchers::HeaderExactMatcher {
    header("authorization", format!("Bearer {t}").as_str())
}

async fn requests_to(s: &MockServer, needle: &str) -> Vec<String> {
    s.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().contains(needle))
        .map(|r| {
            r.headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default()
        })
        .collect()
}

fn org(id: &str) -> Scope {
    format!("organizations/{id}").parse().unwrap()
}

fn spec(values: &[&str]) -> serde_json::Value {
    json!({"spec": {"etag": "e", "rules": [{"values": {"allowedValues": values}}]}})
}

fn export_path(o: &str) -> String {
    format!("/v2/organizations/{o}/policies/resourcemanager.allowedExportDestinations")
}
fn import_path(o: &str) -> String {
    format!("/v2/organizations/{o}/policies/resourcemanager.allowedImportSources")
}

#[tokio::test]
async fn each_org_is_read_with_its_own_login_and_the_owner_is_learned() {
    let t = split().await;
    Mock::given(method("GET"))
        .and(path(export_path("111")))
        .and(bearer(SRC_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(spec(&["under:organizations/999"])))
        .mount(&t.src)
        .await;
    Mock::given(method("GET"))
        .and(path(import_path("222")))
        .and(bearer(DST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(spec(&["under:organizations/888"])))
        .mount(&t.dst)
        .await;

    let src = t
        .gcp
        .get_policy(&org("111"), EXPORT)
        .await
        .unwrap()
        .unwrap();
    assert!(src.allows("under:organizations/999"));
    // Unknown owner: the source login is tried first, is refused, then the destination login works.
    let dst = t
        .gcp
        .get_policy(&org("222"), IMPORT)
        .await
        .unwrap()
        .unwrap();
    assert!(dst.allows("under:organizations/888"));
    assert_eq!(
        requests_to(&t.src, "organizations/222").await,
        vec!["Bearer src-token"],
        "tried and refused"
    );
    assert_eq!(
        requests_to(&t.dst, "organizations/222").await,
        vec!["Bearer dst-token"]
    );

    // Learned: the next call goes straight to the destination login.
    t.gcp.get_policy(&org("222"), IMPORT).await.unwrap();
    assert_eq!(
        requests_to(&t.src, "organizations/222").await.len(),
        1,
        "no second attempt on the source side"
    );
    assert_eq!(requests_to(&t.dst, "organizations/222").await.len(), 2);
    // And the source org never touched the destination login.
    assert!(requests_to(&t.dst, "organizations/111").await.is_empty());
}

#[tokio::test]
async fn hints_avoid_the_wasted_first_attempt() {
    let t = split().await;
    t.gcp.hint_org(&"111".parse().unwrap(), Side::Source);
    t.gcp.hint_org(&"222".parse().unwrap(), Side::Destination);
    Mock::given(method("GET"))
        .and(path(import_path("222")))
        .and(bearer(DST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(spec(&["x"])))
        .mount(&t.dst)
        .await;
    t.gcp.get_policy(&org("222"), IMPORT).await.unwrap();
    assert!(
        requests_to(&t.src, "organizations/222").await.is_empty(),
        "went straight to the destination login"
    );
}

#[tokio::test]
async fn constraints_are_written_with_the_login_of_the_org_they_belong_to() {
    let t = split().await;
    t.gcp.hint_org(&"111".parse().unwrap(), Side::Source);
    t.gcp.hint_org(&"222".parse().unwrap(), Side::Destination);
    for (server, tok, p) in [
        (&t.src, SRC_TOKEN, export_path("111")),
        (&t.dst, DST_TOKEN, import_path("222")),
    ] {
        Mock::given(method("GET"))
            .and(path(p.clone()))
            .and(bearer(tok))
            .respond_with(missing())
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                p.rsplit_once("/policies/").unwrap().0.to_string() + "/policies",
            ))
            .and(bearer(tok))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "x"})))
            .expect(1)
            .mount(server)
            .await;
    }
    let mut export = OrgPolicy::empty(EXPORT);
    export.allow_value("under:organizations/222");
    t.gcp.set_policy(&org("111"), export).await.unwrap();
    let mut import = OrgPolicy::empty(IMPORT);
    import.allow_value("under:organizations/111");
    t.gcp.set_policy(&org("222"), import).await.unwrap();
    // `expect(1)` on each server verifies on drop that the right login made exactly one create.
}

#[tokio::test]
async fn the_move_uses_the_chosen_movers_login_and_polling_follows_it() {
    for (mover, token, other_is_dst) in [
        (Side::Source, SRC_TOKEN, true),
        (Side::Destination, DST_TOKEN, false),
    ] {
        let t = split_with(mover).await;
        let (mover_srv, other_srv) = if other_is_dst {
            (&t.src, &t.dst)
        } else {
            (&t.dst, &t.src)
        };
        Mock::given(method("POST"))
            .and(path("/v3/projects/my-app-prod:move"))
            .and(bearer(token))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"name": "operations/cp.1", "done": false})),
            )
            .expect(1)
            .mount(mover_srv)
            .await;
        Mock::given(method("GET")).and(path("/v3/operations/cp.1")).and(bearer(token))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "operations/cp.1", "done": true,
                "response": {"@type": "type.googleapis.com/google.cloud.resourcemanager.v3.Project", "name": "projects/9"}}))).mount(mover_srv).await;
        let op = t
            .gcp
            .move_project(
                &"my-app-prod".parse().unwrap(),
                &"folders/20".parse().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            t.gcp.poll_operation(&op).await.unwrap(),
            OperationStatus::Done
        );
        assert!(
            requests_to(other_srv, "my-app-prod:move").await.is_empty(),
            "{mover:?}: the other login never calls move"
        );
        assert!(
            requests_to(other_srv, "operations").await.is_empty(),
            "{mover:?}: polling stays with the mover"
        );
    }
}

#[tokio::test]
async fn after_a_move_the_project_is_read_with_the_destination_login() {
    let t = split().await;
    t.gcp
        .hint(&"folders/20".parse().unwrap(), Side::Destination);
    Mock::given(method("POST"))
        .and(path("/v3/projects/my-app-prod:move"))
        .and(bearer(SRC_TOKEN))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"name": "operations/cp.1", "done": false})),
        )
        .mount(&t.src)
        .await;
    Mock::given(method("GET")).and(path("/v3/operations/cp.1")).and(bearer(SRC_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "operations/cp.1", "done": true,
            "response": {"@type": "type.googleapis.com/google.cloud.resourcemanager.v3.Project", "name": "projects/9"}}))).mount(&t.src).await;
    // After the move only the destination login can see the project.
    Mock::given(method("GET"))
        .and(path("/v3/projects/my-app-prod"))
        .and(bearer(DST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(project_json(
            "my-app-prod",
            "9",
            "folders/20",
        )))
        .mount(&t.dst)
        .await;
    let op = t
        .gcp
        .move_project(
            &"my-app-prod".parse().unwrap(),
            &"folders/20".parse().unwrap(),
        )
        .await
        .unwrap();
    t.gcp.poll_operation(&op).await.unwrap();
    let p = t
        .gcp
        .get_project(&"my-app-prod".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(p.parent.to_string(), "folders/20");
    assert!(
        requests_to(&t.src, "/v3/projects/my-app-prod")
            .await
            .iter()
            .all(|_| false)
            || requests_to(&t.src, "projects/my-app-prod").await.len() == 1,
        "only the move call itself, no read attempt on the source side"
    );
}

#[tokio::test]
async fn a_moved_project_found_by_a_fresh_process_falls_back_to_the_destination_login() {
    let t = split().await;
    Mock::given(method("GET"))
        .and(path("/v3/projects/my-app-prod"))
        .and(bearer(DST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(project_json(
            "my-app-prod",
            "9",
            "folders/20",
        )))
        .mount(&t.dst)
        .await;
    let p = t
        .gcp
        .get_project(&"my-app-prod".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(p.number.as_str(), "9");
    assert_eq!(
        requests_to(&t.src, "my-app-prod").await.len(),
        1,
        "source login tried first and refused"
    );
    // learned
    t.gcp
        .get_project(&"my-app-prod".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(requests_to(&t.src, "my-app-prod").await.len(), 1);
}

#[tokio::test]
async fn move_permissions_are_tested_as_the_mover_even_on_destination_resources() {
    let t = split_with(Side::Source).await;
    Mock::given(method("POST"))
        .and(path("/v3/folders/20:testIamPermissions"))
        .and(bearer(SRC_TOKEN))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"permissions": ["resourcemanager.projects.create"]})),
        )
        .expect(1)
        .mount(&t.src)
        .await;
    let got = t
        .gcp
        .test_move_permissions(
            &"folders/20".parse().unwrap(),
            &["resourcemanager.projects.create".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(got, ["resourcemanager.projects.create"]);
    assert!(
        requests_to(&t.dst, "folders/20").await.is_empty(),
        "the destination login is not consulted for the mover's rights"
    );
}

#[tokio::test]
async fn analyze_move_is_asked_as_the_mover() {
    let t = split_with(Side::Destination).await;
    Mock::given(method("GET"))
        .and(path("/v1/projects/my-app-prod:analyzeMove"))
        .and(bearer(DST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"moveAnalysis": []})))
        .expect(1)
        .mount(&t.dst)
        .await;
    t.gcp
        .analyze_move(
            &"my-app-prod".parse().unwrap(),
            &"folders/20".parse().unwrap(),
        )
        .await
        .unwrap();
    assert!(requests_to(&t.src, "analyzeMove").await.is_empty());
}

#[tokio::test]
async fn when_neither_login_can_reach_it_both_are_named() {
    let t = split().await;
    let e = t
        .gcp
        .get_project(&"ghost-project".parse().unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::PermissionDenied);
    assert!(
        e.message.contains("source") && e.message.contains("destination"),
        "{}",
        e.message
    );
    assert!(e.hint.is_some());
}

#[tokio::test]
async fn a_known_owner_that_says_not_found_is_authoritative() {
    let t = split().await;
    t.gcp.hint_org(&"222".parse().unwrap(), Side::Destination);
    Mock::given(method("GET"))
        .and(path("/v1/organizations/222/roles/deployer"))
        .and(bearer(DST_TOKEN))
        .respond_with(missing())
        .mount(&t.dst)
        .await;
    // The source login's 403 must not turn "the role does not exist" into an error.
    assert!(t
        .gcp
        .get_custom_role(&RoleName::new("organizations/222/roles/deployer"))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn group_lookup_only_falls_back_on_denied_never_on_not_found() {
    let t = split().await;
    Mock::given(method("GET"))
        .and(path("/v1/groups:lookup"))
        .and(bearer(SRC_TOKEN))
        .respond_with(ResponseTemplate::new(404))
        .mount(&t.src)
        .await;
    assert!(
        !t.gcp.group_exists("ghost@x.com").await.unwrap(),
        "a 404 is an answer, not a reason to try the other login"
    );
    assert!(requests_to(&t.dst, "groups").await.is_empty());
}

#[tokio::test]
async fn each_side_sends_its_own_quota_project() {
    let t = split().await;
    t.gcp.hint_org(&"111".parse().unwrap(), Side::Source);
    t.gcp.hint_org(&"222".parse().unwrap(), Side::Destination);
    for (srv, tok, o) in [(&t.src, SRC_TOKEN, "111"), (&t.dst, DST_TOKEN, "222")] {
        Mock::given(method("GET"))
            .and(path(export_path(o)))
            .and(bearer(tok))
            .respond_with(ResponseTemplate::new(200).set_body_json(spec(&["x"])))
            .mount(srv)
            .await;
    }
    t.gcp.get_policy(&org("111"), EXPORT).await.unwrap();
    t.gcp.get_policy(&org("222"), EXPORT).await.unwrap();
    async fn quota(s: &MockServer) -> Vec<String> {
        s.received_requests()
            .await
            .unwrap()
            .iter()
            .filter_map(|r| {
                r.headers
                    .get("x-goog-user-project")
                    .map(|v| v.to_str().unwrap().to_string())
            })
            .collect()
    }
    assert_eq!(quota(&t.src).await, vec!["src-quota"]);
    assert_eq!(quota(&t.dst).await, vec!["dst-quota"]);
}

#[tokio::test]
async fn ancestry_is_walked_with_the_login_that_owns_each_step() {
    let t = split().await;
    // source project under a source folder under the source org
    Mock::given(method("GET"))
        .and(path("/v3/projects/my-app-prod"))
        .and(bearer(SRC_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(project_json(
            "my-app-prod",
            "9",
            "folders/10",
        )))
        .mount(&t.src)
        .await;
    Mock::given(method("GET"))
        .and(path("/v3/folders/10"))
        .and(bearer(SRC_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"name": "folders/10", "parent": "organizations/111", "state": "ACTIVE"}),
        ))
        .mount(&t.src)
        .await;
    // destination folder under the destination org
    Mock::given(method("GET"))
        .and(path("/v3/folders/20"))
        .and(bearer(DST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"name": "folders/20", "parent": "organizations/222", "state": "ACTIVE"}),
        ))
        .mount(&t.dst)
        .await;
    let a = t
        .gcp
        .get_ancestry(&"my-app-prod".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        a.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["folders/10", "organizations/111"]
    );
    let b = t
        .gcp
        .get_folder_ancestry(&"20".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        b.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["organizations/222"]
    );
    assert!(
        requests_to(&t.dst, "folders/10").await.is_empty(),
        "the source folder is never sent to the destination login"
    );
}

#[tokio::test]
async fn with_one_login_nothing_is_routed_or_retried() {
    let server = locked_server().await;
    let cfg = Config::single(
        static_token_credentials(SRC_TOKEN, None),
        4,
        Some(server.uri()),
    );
    let gcp = RealGcp::new(cfg);
    assert!(!gcp.is_split());
    let e = gcp
        .get_project(&"my-app-prod".parse().unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::PermissionDenied);
    assert_eq!(
        requests_to(&server, "my-app-prod").await.len(),
        1,
        "a single attempt: there is no other login to try"
    );
    assert!(!e.message.contains("tried the"), "{}", e.message);
}
