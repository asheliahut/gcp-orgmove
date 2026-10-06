mod common;

use common::*;
use gcp_orgmove_core::*;
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

fn pid(s: &str) -> ProjectId {
    s.parse().unwrap()
}

fn not_found() -> ResponseTemplate {
    ResponseTemplate::new(404)
        .set_body_json(json!({"error": {"code": 404, "message": "none", "status": "NOT_FOUND"}}))
}

#[tokio::test]
async fn deny_policies_use_the_encoded_attachment_point_and_convert_rules() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path(
            "/v2/policies/cloudresourcemanager.googleapis.com%2Ffolders%2F10/denypolicies",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "policies": [{
                "name": "policies/x/denypolicies/block-delete",
                "rules": [
                    {"denyRule": {
                        "deniedPrincipals": ["principalSet://goog/public:all"],
                        "exceptionPrincipals": ["principal://goog/subject/admin@x.com"],
                        "deniedPermissions": ["iam.googleapis.com/roles.delete"],
                        "denialCondition": {"expression": "true"}}},
                    {"description": "not a deny rule"}
                ]
            }]
        })))
        .mount(&s)
        .await;
    let r: Resource = "folders/10".parse().unwrap();
    let policies = gcp.list_deny_policies(&r).await.unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].attached_to, r);
    assert_eq!(policies[0].rules.len(), 1);
    let rule = &policies[0].rules[0];
    assert!(rule
        .denied_permissions
        .contains("iam.googleapis.com/roles.delete"));
    assert!(rule.has_condition);
    assert_eq!(rule.exception_principals.len(), 1);
}

#[tokio::test]
async fn deny_policies_empty_when_none() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&s)
        .await;
    assert!(gcp
        .list_deny_policies(&"organizations/111".parse().unwrap())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn troubleshoot_reports_granted_per_permission() {
    let (s, gcp) = server().await;
    Mock::given(method("POST"))
        .and(path("/v1/iam:troubleshoot"))
        .and(body_partial_json(json!({"accessTuple": {
            "principal": "serviceAccount:deployer@my-app-prod.iam.gserviceaccount.com",
            "fullResourceName": "//cloudresourcemanager.googleapis.com/projects/my-app-prod",
            "permission": "compute.instances.get"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access": 1})))
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/iam:troubleshoot"))
        .and(body_partial_json(
            json!({"accessTuple": {"permission": "storage.objects.get"}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access": 2})))
        .mount(&s)
        .await;
    let v = gcp
        .troubleshoot_access(
            &"projects/my-app-prod".parse().unwrap(),
            "serviceAccount:deployer@my-app-prod.iam.gserviceaccount.com",
            &[
                "compute.instances.get".to_string(),
                "storage.objects.get".to_string(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(v.len(), 2);
    assert!(v[0].granted && v[0].permission == "compute.instances.get");
    assert!(!v[1].granted);
}

#[tokio::test]
async fn firewall_policy_associations_for_a_folder() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/compute/v1/locations/global/firewallPolicies/listAssociations"))
        .and(query_param("targetResource", "folders/10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "associations": [
                {"attachmentTarget": "folders/10", "firewallPolicyId": "123", "shortName": "corp-baseline"},
                {"attachmentTarget": "folders/10", "firewallPolicyId": "456"}
            ]
        })))
        .mount(&s)
        .await;
    let fp = gcp
        .list_firewall_policies(&"folders/10".parse().unwrap())
        .await
        .unwrap();
    let names: Vec<_> = fp.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["456", "corp-baseline"]);
}

#[tokio::test]
async fn shared_vpc_service_project_links_to_host() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/compute/v1/projects/app-svc-aaa/getXpnHost"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"name": "net-host-aa", "kind": "compute#project"})),
        )
        .mount(&s)
        .await;
    let links = gcp
        .shared_vpc_relationships(&pid("app-svc-aaa"))
        .await
        .unwrap();
    assert_eq!(
        links,
        vec![SharedVpcLink {
            host: pid("net-host-aa"),
            service: pid("app-svc-aaa")
        }]
    );
}

#[tokio::test]
async fn shared_vpc_host_lists_service_projects() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/compute/v1/projects/net-host-aa/getXpnHost"))
        .respond_with(not_found())
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/compute/v1/projects/net-host-aa/getXpnResources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resources": [{"id": "app-svc-bbb", "type": "PROJECT"}, {"id": "app-svc-aaa", "type": "PROJECT"}]
        })))
        .mount(&s)
        .await;
    let links = gcp
        .shared_vpc_relationships(&pid("net-host-aa"))
        .await
        .unwrap();
    let services: Vec<_> = links.iter().map(|l| l.service.as_str()).collect();
    assert_eq!(services, ["app-svc-aaa", "app-svc-bbb"]);
    assert!(links.iter().all(|l| l.host == pid("net-host-aa")));
}

#[tokio::test]
async fn shared_vpc_plain_project_has_no_links() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/compute/v1/projects/plain-proj/getXpnHost"))
        .respond_with(not_found())
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/compute/v1/projects/plain-proj/getXpnResources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&s)
        .await;
    assert!(gcp
        .shared_vpc_relationships(&pid("plain-proj"))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn shared_vpc_permission_errors_propagate() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": {"code": 403, "message": "api disabled", "status": "PERMISSION_DENIED"}})))
        .mount(&s)
        .await;
    assert_eq!(
        gcp.shared_vpc_relationships(&pid("plain-proj"))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn vpc_sc_perimeters_collect_project_numbers_from_status_and_spec() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v1/accessPolicies"))
        .and(query_param("parent", "organizations/111"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessPolicies": [{"name": "accessPolicies/555", "parent": "organizations/111", "title": "p"}]
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/accessPolicies/555/servicePerimeters"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "servicePerimeters": [{
                "name": "accessPolicies/555/servicePerimeters/prod",
                "title": "prod",
                "status": {"resources": ["projects/1001", "projects/1002"]},
                "spec": {"resources": ["projects/1002", "projects/1003"]}
            }]
        })))
        .mount(&s)
        .await;
    let ps = gcp
        .list_vpc_sc_perimeters(&"111".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(ps.len(), 1);
    let nums: Vec<_> = ps[0].projects.iter().map(|n| n.as_str()).collect();
    assert_eq!(nums, ["1001", "1002", "1003"]);
}

#[tokio::test]
async fn group_lookup_goes_through_reqwest_with_the_query() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v1/groups:lookup"))
        .and(query_param("groupKey.id", "eng@example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "groups/1"})))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(query_param("groupKey.id", "ghost@example.com"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&s)
        .await;
    assert!(gcp.group_exists("eng@example.com").await.unwrap());
    assert!(!gcp.group_exists("ghost@example.com").await.unwrap());
}

#[tokio::test]
async fn org_scoped_items_cover_sinks_tags_and_feeds() {
    let (s, gcp) = server().await;
    Mock::given(method("GET"))
        .and(path("/v2/organizations/111/sinks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sinks": [
                {"name": "org-audit", "destination": "storage.googleapis.com/audit-bucket", "filter": "logName:cloudaudit", "includeChildren": true},
                {"name": "org-only", "destination": "storage.googleapis.com/x", "includeChildren": false},
                {"name": "org-off", "destination": "storage.googleapis.com/y", "includeChildren": true, "disabled": true}
            ]
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v3/projects/proj-aaaa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(project_json(
            "proj-aaaa",
            "1001",
            "folders/10",
        )))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v3/tagBindings"))
        .and(query_param("parent", "//cloudresourcemanager.googleapis.com/projects/1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tagBindings": [{"name": "tagBindings/x", "parent": "//cloudresourcemanager.googleapis.com/projects/1001",
                             "tagValue": "tagValues/123", "tagValueNamespacedName": "111/env/prod"}]
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/organizations/111/feeds"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "feeds": [{"name": "organizations/111/feeds/iam-changes", "assetNames": ["//cloudresourcemanager.googleapis.com/projects/1001"]}]
        })))
        .mount(&s)
        .await;
    let items = gcp
        .list_org_scoped(&"111".parse().unwrap(), &pid("proj-aaaa"))
        .await
        .unwrap();
    let kinds: Vec<_> = items
        .iter()
        .map(|i| (i.kind.as_str(), i.name.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("asset_feed", "organizations/111/feeds/iam-changes"),
            ("log_sink", "org-audit"),
            ("tag_binding", "tagValues/123")
        ],
        "only enabled sinks that include children are relevant"
    );
    assert!(items[1].detail.contains("audit-bucket"));
    assert_eq!(items[2].detail, "111/env/prod");
}
