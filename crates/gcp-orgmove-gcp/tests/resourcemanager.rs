mod common;

use common::*;
use gcp_orgmove_core::*;
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

fn pid(s: &str) -> ProjectId {
    s.parse().unwrap()
}

#[tokio::test]
async fn get_project_converts_fields() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v3/projects/my-app-prod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(project_json(
            "my-app-prod",
            "123456789",
            "folders/10",
        )))
        .mount(&s)
        .await;
    let p = gcp.get_project(&pid("my-app-prod")).await.unwrap();
    assert_eq!(p.number.as_str(), "123456789");
    assert_eq!(p.parent.to_string(), "folders/10");
    assert_eq!(p.state, LifecycleState::Active);
    assert_eq!(p.labels["env"], "prod");
}

#[tokio::test]
async fn permission_denied_maps_to_exit_3() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).set_body_json(
            json!({"error": {"code": 403, "message": "nope", "status": "PERMISSION_DENIED"}}),
        ))
        .mount(&s)
        .await;
    let e = gcp.get_project(&pid("my-app-prod")).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::PermissionDenied);
    assert_eq!(e.exit_code(), 3);
    assert!(e.message.contains("projects/my-app-prod"));
}

#[tokio::test]
async fn not_found_maps_to_not_found() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            json!({"error": {"code": 404, "message": "gone", "status": "NOT_FOUND"}}),
        ))
        .mount(&s)
        .await;
    assert_eq!(
        gcp.get_project(&pid("my-app-prod")).await.unwrap_err().kind,
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn list_projects_recurses_folders_and_paginates() {
    let (s, gcp) = server().await;
    // org: one project (2 pages) + one folder; folder: one project
    Mock::given(method("GET"))
        .and(path("/v3/projects"))
        .and(query_param("parent", "organizations/111"))
        .and(query_param("pageToken", ""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [project_json("proj-aaaa", "1", "organizations/111")],
            "nextPageToken": "t2"
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v3/projects"))
        .and(query_param("parent", "organizations/111"))
        .and(query_param("pageToken", "t2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [project_json("proj-bbbb", "2", "organizations/111")]
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v3/folders"))
        .and(query_param("parent", "organizations/111"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "folders": [{"name": "folders/10", "parent": "organizations/111", "displayName": "f", "state": "ACTIVE"}]
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v3/folders"))
        .and(query_param("parent", "folders/10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v3/projects"))
        .and(query_param("parent", "folders/10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [project_json("proj-cccc", "3", "folders/10")]
        })))
        .mount(&s)
        .await;
    let all = gcp
        .list_projects(&"organizations/111".parse().unwrap())
        .await
        .unwrap();
    let ids: Vec<_> = all.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["proj-aaaa", "proj-bbbb", "proj-cccc"]);
}

#[tokio::test]
async fn ancestry_walks_folders_to_the_org() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v3/projects/my-app-prod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(project_json(
            "my-app-prod",
            "9",
            "folders/20",
        )))
        .mount(&s)
        .await;
    for (f, parent) in [("20", "folders/10"), ("10", "organizations/111")] {
        Mock::given(method("GET"))
            .and(path(format!("/v3/folders/{f}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"name": format!("folders/{f}"), "parent": parent, "state": "ACTIVE"}),
            ))
            .mount(&s)
            .await;
    }
    let a = gcp.get_ancestry(&pid("my-app-prod")).await.unwrap();
    let a: Vec<String> = a.iter().map(ToString::to_string).collect();
    assert_eq!(a, ["folders/20", "folders/10", "organizations/111"]);
}

#[tokio::test]
async fn move_project_sends_destination_and_poll_maps_status() {
    let (s, gcp) = server().await;
    Mock::given(method("POST"))
        .and(path("/v3/projects/my-app-prod:move"))
        .and(body_partial_json(
            json!({"destinationParent": "folders/20"}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"name": "operations/cp.1", "done": false})),
        )
        .expect(1)
        .mount(&s)
        .await;
    let op = gcp
        .move_project(&pid("my-app-prod"), &"folders/20".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(op.name, "operations/cp.1");

    Mock::given(method("GET"))
        .and(path("/v3/operations/cp.1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"name": "operations/cp.1", "done": false})),
        )
        .up_to_n_times(1)
        .mount(&s)
        .await;
    assert_eq!(
        gcp.poll_operation(&op).await.unwrap(),
        OperationStatus::Running
    );
    s.reset().await;

    Mock::given(method("GET"))
        .and(path("/v3/operations/cp.1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "operations/cp.1", "done": true,
            "response": {"@type": "type.googleapis.com/google.cloud.resourcemanager.v3.Project", "name": "projects/9"}
        })))
        .mount(&s)
        .await;
    assert_eq!(
        gcp.poll_operation(&op).await.unwrap(),
        OperationStatus::Done
    );

    s.reset().await;
    Mock::given(method("GET"))
        .and(path("/v3/operations/cp.1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "operations/cp.1", "done": true,
            "error": {"code": 9, "message": "constraint violated"}
        })))
        .mount(&s)
        .await;
    match gcp.poll_operation(&op).await.unwrap() {
        OperationStatus::Failed { message, .. } => assert!(message.contains("constraint violated")),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn move_429_is_retried_then_succeeds() {
    let (s, gcp) = server().await;
    Mock::given(method("POST"))
        .and(path("/v3/projects/my-app-prod:move"))
        .respond_with(ResponseTemplate::new(429).set_body_json(
            json!({"error": {"code": 429, "message": "slow down", "status": "RESOURCE_EXHAUSTED"}}),
        ))
        .up_to_n_times(1)
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/v3/projects/my-app-prod:move"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"name": "operations/cp.2", "done": false})),
        )
        .mount(&s)
        .await;
    let op = gcp
        .move_project(&pid("my-app-prod"), &"folders/20".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(op.name, "operations/cp.2");
}

#[tokio::test]
async fn permission_failure_is_not_retried() {
    let (s, gcp) = server().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(
            json!({"error": {"code": 403, "message": "no", "status": "PERMISSION_DENIED"}}),
        ))
        .expect(1)
        .mount(&s)
        .await;
    let e = gcp
        .move_project(&pid("my-app-prod"), &"folders/20".parse().unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn iam_get_requests_v3_and_set_conflict_maps_to_conflict() {
    let (s, gcp) = server().await;
    Mock::given(method("POST"))
        .and(path("/v3/projects/my-app-prod:getIamPolicy"))
        .and(body_partial_json(
            json!({"options": {"requestedPolicyVersion": 3}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": 3, "etag": "BwYAAQ==",
            "bindings": [{"role": "roles/viewer", "members": ["user:a@x.com"]}]
        })))
        .mount(&s)
        .await;
    let r: Resource = "projects/my-app-prod".parse().unwrap();
    let p = gcp.get_iam(&r).await.unwrap();
    assert_eq!(p.bindings[0].role.as_str(), "roles/viewer");
    assert!(!p.etag.is_empty());

    Mock::given(method("POST"))
        .and(path("/v3/projects/my-app-prod:setIamPolicy"))
        .and(body_partial_json(json!({"policy": {"version": 3}})))
        .respond_with(ResponseTemplate::new(409).set_body_json(
            json!({"error": {"code": 409, "message": "etag mismatch", "status": "ABORTED"}}),
        ))
        .mount(&s)
        .await;
    let e = gcp.set_iam(&r, p).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Conflict);
}

#[tokio::test]
async fn test_permissions_returns_granted_subset() {
    let (s, gcp) = server().await;
    Mock::given(method("POST"))
        .and(path("/v3/folders/10:testIamPermissions"))
        .and(body_partial_json(json!({"permissions": ["resourcemanager.projects.create", "resourcemanager.projects.move"]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"permissions": ["resourcemanager.projects.create"]})))
        .mount(&s)
        .await;
    let got = gcp
        .test_permissions(
            &"folders/10".parse().unwrap(),
            &[
                "resourcemanager.projects.create".to_string(),
                "resourcemanager.projects.move".to_string(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(got, ["resourcemanager.projects.create"]);
}

#[tokio::test]
async fn effective_iam_collects_from_each_ancestor() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v3/projects/my-app-prod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(project_json(
            "my-app-prod",
            "9",
            "folders/10",
        )))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v3/folders/10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"name": "folders/10", "parent": "organizations/111", "state": "ACTIVE"}),
        ))
        .mount(&s)
        .await;
    for (res, role) in [
        ("projects/my-app-prod", "roles/owner"),
        ("folders/10", "roles/editor"),
        ("organizations/111", "roles/viewer"),
    ] {
        Mock::given(method("POST"))
            .and(path(format!("/v3/{res}:getIamPolicy")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": 3, "etag": "AA==", "bindings": [{"role": role, "members": ["group:eng@x.com"]}]})))
            .mount(&s)
            .await;
    }
    let eff = gcp
        .get_effective_iam(&"projects/my-app-prod".parse().unwrap())
        .await
        .unwrap();
    let from: Vec<String> = eff.grants.iter().map(|g| g.from.to_string()).collect();
    assert_eq!(
        from,
        ["projects/my-app-prod", "folders/10", "organizations/111"]
    );
}

#[tokio::test]
async fn set_project_labels_waits_for_the_operation() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v3/projects/my-app-prod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(project_json(
            "my-app-prod",
            "9",
            "folders/10",
        )))
        .mount(&s)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/v3/projects/9"))
        .and(query_param("updateMask", "labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "operations/up.1", "done": true,
            "response": {
                "@type": "type.googleapis.com/google.cloud.resourcemanager.v3.Project",
                "name": "projects/9", "parent": "folders/10", "projectId": "my-app-prod",
                "state": "ACTIVE", "etag": "e2", "labels": {"orgmove-override-exp": "20261104"}
            }
        })))
        .mount(&s)
        .await;
    let p = gcp
        .set_project_labels(
            &pid("my-app-prod"),
            [("orgmove-override-exp".to_string(), "20261104".to_string())].into(),
        )
        .await
        .unwrap();
    assert_eq!(p.labels["orgmove-override-exp"], "20261104");
}
