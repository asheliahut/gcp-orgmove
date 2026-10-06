mod common;

use std::collections::BTreeSet;

use common::*;
use gcp_orgmove_core::*;
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const EXPORT: &str = "constraints/resourcemanager.allowedExportDestinations";
const EXPORT_NAME: &str =
    "/v2/organizations/111/policies/resourcemanager.allowedExportDestinations";

fn org() -> Scope {
    "organizations/111".parse().unwrap()
}

#[tokio::test]
async fn analyze_move_classifies_blockers_warnings_and_errors() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v1/projects/my-app-prod:analyzeMove"))
        .and(query_param("destinationParent", "folders/20"))
        .and(query_param("view", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "moveAnalysis": [
                {"displayName": "IAM policy", "analysis": {
                    "blockers": [{"detail": "Shared VPC host project"}],
                    "warnings": [{"detail": "org policy differs"}]}},
                {"displayName": "Org policy", "error": {"code": 7, "message": "denied"}}
            ]
        })))
        .mount(&s)
        .await;
    let a = gcp
        .analyze_move(
            &"my-app-prod".parse().unwrap(),
            &"folders/20".parse().unwrap(),
        )
        .await
        .unwrap();
    let blockers: Vec<_> = a
        .of(AnalysisLevel::Blocker)
        .map(|i| i.message.clone())
        .collect();
    assert_eq!(blockers.len(), 2);
    assert!(blockers[0].contains("Shared VPC"));
    assert!(blockers[1].contains("analysis failed: denied"));
    assert_eq!(a.of(AnalysisLevel::Warning).count(), 1);
}

#[tokio::test]
async fn get_policy_is_none_when_not_found_and_converts_spec() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path(EXPORT_NAME))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            json!({"error": {"code": 404, "message": "none", "status": "NOT_FOUND"}}),
        ))
        .up_to_n_times(1)
        .mount(&s)
        .await;
    assert!(gcp.get_policy(&org(), EXPORT).await.unwrap().is_none());

    Mock::given(method("GET"))
        .and(path(EXPORT_NAME))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "organizations/111/policies/resourcemanager.allowedExportDestinations",
            "spec": {"etag": "abc", "inheritFromParent": false,
                     "rules": [{"values": {"allowedValues": ["under:organizations/999"]}}]}
        })))
        .mount(&s)
        .await;
    let p = gcp.get_policy(&org(), EXPORT).await.unwrap().unwrap();
    assert!(p.allows("under:organizations/999"));
    assert_eq!(p.etag, "abc");
    assert_eq!(p.constraint, EXPORT);
}

#[tokio::test]
async fn set_policy_creates_when_absent() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path(EXPORT_NAME))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            json!({"error": {"code": 404, "message": "none", "status": "NOT_FOUND"}}),
        ))
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/organizations/111/policies"))
        .and(body_partial_json(json!({
            "name": "organizations/111/policies/resourcemanager.allowedExportDestinations",
            "spec": {"rules": [{"values": {"allowedValues": ["under:organizations/222"]}}]}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "x"})))
        .expect(1)
        .mount(&s)
        .await;
    let mut p = OrgPolicy::empty(EXPORT);
    p.allow_value("under:organizations/222");
    gcp.set_policy(&org(), p).await.unwrap();
}

#[tokio::test]
async fn set_policy_updates_existing_with_etag_and_maps_conflict() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path(EXPORT_NAME))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "organizations/111/policies/resourcemanager.allowedExportDestinations",
            "spec": {"etag": "old", "rules": []}
        })))
        .mount(&s)
        .await;
    Mock::given(method("PATCH"))
        .and(path(EXPORT_NAME))
        .and(body_partial_json(json!({"spec": {"etag": "old"}})))
        .respond_with(
            ResponseTemplate::new(409).set_body_json(
                json!({"error": {"code": 409, "message": "etag", "status": "ABORTED"}}),
            ),
        )
        .mount(&s)
        .await;
    let mut p = OrgPolicy::empty(EXPORT);
    p.etag = "old".into();
    p.allow_value("v");
    assert_eq!(
        gcp.set_policy(&org(), p).await.unwrap_err().kind,
        ErrorKind::Conflict
    );
}

#[tokio::test]
async fn delete_policy_ignores_not_found() {
    let (s, gcp) = server().await;
    Mock::given(method("DELETE"))
        .and(path(EXPORT_NAME))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            json!({"error": {"code": 404, "message": "none", "status": "NOT_FOUND"}}),
        ))
        .mount(&s)
        .await;
    gcp.delete_policy(&org(), EXPORT).await.unwrap();
}

#[tokio::test]
async fn effective_policy_uses_the_effective_endpoint() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v2/projects/my-app-prod/policies/resourcemanager.allowedImportSources:getEffectivePolicy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "projects/my-app-prod/policies/resourcemanager.allowedImportSources",
            "spec": {"rules": [{"values": {"allowedValues": ["under:organizations/111"]}}]}
        })))
        .mount(&s)
        .await;
    let p = gcp
        .get_effective_policy(
            &"projects/my-app-prod".parse().unwrap(),
            "constraints/resourcemanager.allowedImportSources",
        )
        .await
        .unwrap();
    assert!(p.allows("under:organizations/111"));
}

#[tokio::test]
async fn list_policies_pages_and_restores_constraint_names() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v2/organizations/111/policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "policies": [
                {"name": "organizations/111/policies/compute.requireOsLogin", "spec": {"rules": [{"enforce": true}]}},
                {"name": "organizations/111/policies/iam.allowedPolicyMemberDomains", "spec": {"rules": [{"values": {"allowedValues": ["C0123"]}}]}}
            ]
        })))
        .mount(&s)
        .await;
    let ps = gcp.list_policies(&org()).await.unwrap();
    assert_eq!(ps[0].constraint, "constraints/compute.requireOsLogin");
    assert_eq!(ps[0].rules[0].enforce, Some(true));
    assert_eq!(
        ps[1].constraint,
        "constraints/iam.allowedPolicyMemberDomains"
    );
}

fn role_json(name: &str, perms: &[&str]) -> serde_json::Value {
    json!({"name": name, "title": "Deployer", "description": "d", "includedPermissions": perms, "stage": "GA", "etag": "BwY="})
}

#[tokio::test]
async fn list_custom_roles_requests_full_view() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v1/roles"))
        .and(query_param("parent", "organizations/111"))
        .and(query_param("view", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "roles": [role_json("organizations/111/roles/deployer", &["compute.instances.get", "storage.objects.get"])]
        })))
        .mount(&s)
        .await;
    let roles = gcp
        .list_custom_roles(&"111".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(
        roles[0].permissions,
        BTreeSet::from([
            "compute.instances.get".to_string(),
            "storage.objects.get".to_string()
        ])
    );
    assert_eq!(roles[0].stage, RoleStage::Ga);
}

#[tokio::test]
async fn get_custom_role_none_on_404() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(
                json!({"error": {"code": 404, "message": "no", "status": "NOT_FOUND"}}),
            ),
        )
        .mount(&s)
        .await;
    assert!(gcp
        .get_custom_role(&RoleName::new("organizations/222/roles/x"))
        .await
        .unwrap()
        .is_none());
}

fn sample_role(org: &str) -> CustomRole {
    CustomRole {
        name: RoleName::new(format!("organizations/{org}/roles/deployer")),
        title: "Deployer".into(),
        description: "d".into(),
        permissions: BTreeSet::from(["compute.instances.get".to_string()]),
        stage: RoleStage::Ga,
    }
}

#[tokio::test]
async fn create_custom_role_sends_role_id_and_permissions() {
    let (s, gcp) = server().await;
    Mock::given(method("POST"))
        .and(path("/v1/organizations/222/roles"))
        .and(body_partial_json(json!({"roleId": "deployer", "role": {"title": "Deployer", "includedPermissions": ["compute.instances.get"], "stage": 2}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(role_json("organizations/222/roles/deployer", &["compute.instances.get"])))
        .expect(1)
        .mount(&s)
        .await;
    let created = gcp
        .create_custom_role(&"222".parse().unwrap(), sample_role("222"))
        .await
        .unwrap();
    assert_eq!(created.name.as_str(), "organizations/222/roles/deployer");
}

#[tokio::test]
async fn create_custom_role_is_idempotent_when_identical_and_conflicts_otherwise() {
    let (s, gcp) = server().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(409).set_body_json(
            json!({"error": {"code": 409, "message": "exists", "status": "ALREADY_EXISTS"}}),
        ))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/organizations/222/roles/deployer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(role_json(
            "organizations/222/roles/deployer",
            &["compute.instances.get"],
        )))
        .up_to_n_times(1)
        .mount(&s)
        .await;
    let org: OrgId = "222".parse().unwrap();
    assert!(gcp
        .create_custom_role(&org, sample_role("222"))
        .await
        .is_ok());

    Mock::given(method("GET"))
        .and(path("/v1/organizations/222/roles/deployer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(role_json(
            "organizations/222/roles/deployer",
            &["storage.objects.get"],
        )))
        .mount(&s)
        .await;
    assert_eq!(
        gcp.create_custom_role(&org, sample_role("222"))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Conflict
    );
}

#[tokio::test]
async fn create_custom_role_rejects_wrong_org_without_calling_the_api() {
    let (s, gcp) = server().await;
    let e = gcp
        .create_custom_role(&"222".parse().unwrap(), sample_role("111"))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidInput);
    assert!(s.received_requests().await.unwrap().is_empty());
}
