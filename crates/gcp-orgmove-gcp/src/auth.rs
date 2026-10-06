//! Credential sources (§10): ADC (official SDK), gcloud, or a raw token.
//!
//! Tokens are never persisted or logged. A `Credentials` value is shared by
//! every SDK client and by the `reqwest` calls for APIs the SDK doesn't cover.

use std::future::Future;
use std::time::{Duration, Instant};

use gcp_orgmove_core::{Error, ErrorKind, Result};
use google_cloud_auth::credentials::{
    self, CacheableResource, Credentials, CredentialsProvider, EntityTag,
};
use google_cloud_auth::errors::CredentialsError;
use http::{header, Extensions, HeaderMap, HeaderName, HeaderValue};
use tokio::sync::Mutex;

pub const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const QUOTA_HEADER: &str = "x-goog-user-project";
/// gcloud tokens last ~1h; refresh well before expiry.
const GCLOUD_REFRESH: Duration = Duration::from_secs(30 * 60);
pub const ENV_TOKEN_VAR: &str = "GCP_ORGMOVE_TOKEN";

/// Where one organization's credentials come from.
///
/// Text form (used by `--token-source`, `--source-auth`, `--destination-auth`):
///
/// | Spec | Meaning |
/// |---|---|
/// | `adc` | Application Default Credentials |
/// | `adc:<file>` | a specific credentials JSON (service account key, `authorized_user`, `external_account`, `impersonated_service_account`) |
/// | `gcloud` | the active `gcloud` account |
/// | `gcloud:<account>` | `gcloud auth print-access-token --account=<account>` |
/// | `env` | the token in `GCP_ORGMOVE_TOKEN` |
/// | `env:<VAR>` | the token in `$VAR` |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthSpec {
    Adc { file: Option<std::path::PathBuf> },
    Gcloud { account: Option<String> },
    Env { var: String },
}

impl Default for AuthSpec {
    fn default() -> Self {
        AuthSpec::Adc { file: None }
    }
}

impl std::str::FromStr for AuthSpec {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (kind, arg) = match s.split_once(':') {
            Some((k, "")) => {
                return Err(Error::invalid(format!(
                    "auth spec {s:?} has nothing after the colon (use {k:?} on its own for the default)"
                )))
            }
            Some((k, a)) => (k, Some(a)),
            None => (s, None),
        };
        match (kind, arg) {
            ("adc", file) => Ok(Self::Adc {
                file: file.map(Into::into),
            }),
            ("gcloud", account) => Ok(Self::Gcloud {
                account: account.map(String::from),
            }),
            ("env", var) => Ok(Self::Env {
                var: var.unwrap_or(ENV_TOKEN_VAR).to_string(),
            }),
            _ => Err(Error::invalid(format!(
                "unknown auth spec {s:?}: expected adc[:file], gcloud[:account] or env[:VAR]"
            ))),
        }
    }
}

impl std::fmt::Display for AuthSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthSpec::Adc { file: None } => write!(f, "adc"),
            AuthSpec::Adc { file: Some(p) } => write!(f, "adc:{}", p.display()),
            AuthSpec::Gcloud { account: None } => write!(f, "gcloud"),
            AuthSpec::Gcloud { account: Some(a) } => write!(f, "gcloud:{a}"),
            AuthSpec::Env { var } if var == ENV_TOKEN_VAR => write!(f, "env"),
            AuthSpec::Env { var } => write!(f, "env:{var}"),
        }
    }
}

fn headers_for(
    token: &str,
    quota_project: Option<&str>,
) -> std::result::Result<HeaderMap, CredentialsError> {
    let mut h = HeaderMap::new();
    let mut v = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
        CredentialsError::from_msg(false, "access token contains invalid header characters")
    })?;
    v.set_sensitive(true);
    h.insert(header::AUTHORIZATION, v);
    if let Some(q) = quota_project {
        let v = HeaderValue::from_str(q)
            .map_err(|_| CredentialsError::from_msg(false, "invalid quota project"))?;
        h.insert(HeaderName::from_static(QUOTA_HEADER), v);
    }
    Ok(h)
}

/// A fixed bearer token (from `GCP_ORGMOVE_TOKEN`).
struct StaticToken {
    token: String,
    quota_project: Option<String>,
}

impl std::fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticToken")
            .field("token", &"[censored]")
            .finish()
    }
}

impl CredentialsProvider for StaticToken {
    fn headers(
        &self,
        _: Extensions,
    ) -> impl Future<Output = std::result::Result<CacheableResource<HeaderMap>, CredentialsError>> + Send
    {
        let r = headers_for(&self.token, self.quota_project.as_deref()).map(|data| {
            CacheableResource::New {
                entity_tag: EntityTag::new(),
                data,
            }
        });
        async move { r }
    }
    async fn universe_domain(&self) -> Option<String> {
        None
    }
}

/// Tokens from `gcloud auth print-access-token`, refreshed periodically.
struct GcloudToken {
    account: Option<String>,
    quota_project: Option<String>,
    cached: Mutex<Option<(String, Instant)>>,
}

impl std::fmt::Debug for GcloudToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcloudToken").finish_non_exhaustive()
    }
}

async fn run_gcloud(account: Option<&str>) -> std::result::Result<String, CredentialsError> {
    let mut cmd = tokio::process::Command::new("gcloud");
    cmd.args(["auth", "print-access-token"]);
    if let Some(a) = account {
        cmd.arg(format!("--account={a}"));
    }
    let out = cmd
        .output()
        .await
        .map_err(|e| CredentialsError::from_msg(false, format!("cannot run gcloud: {e}")))?;
    if !out.status.success() {
        return Err(CredentialsError::from_msg(
            false,
            format!(
                "gcloud auth print-access-token failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if token.is_empty() {
        return Err(CredentialsError::from_msg(
            false,
            "gcloud returned an empty token",
        ));
    }
    Ok(token)
}

impl CredentialsProvider for GcloudToken {
    async fn headers(
        &self,
        _: Extensions,
    ) -> std::result::Result<CacheableResource<HeaderMap>, CredentialsError> {
        let mut cached = self.cached.lock().await;
        let fresh = matches!(&*cached, Some((_, at)) if at.elapsed() < GCLOUD_REFRESH);
        if !fresh {
            *cached = Some((run_gcloud(self.account.as_deref()).await?, Instant::now()));
        }
        let token = &cached.as_ref().expect("just filled").0;
        Ok(CacheableResource::New {
            entity_tag: EntityTag::new(),
            data: headers_for(token, self.quota_project.as_deref())?,
        })
    }
    async fn universe_domain(&self) -> Option<String> {
        None
    }
}

/// A fixed bearer token as SDK credentials (what `env` specs use; also handy in tests).
pub fn static_token_credentials(token: &str, quota_project: Option<&str>) -> Credentials {
    StaticToken {
        token: token.trim().to_string(),
        quota_project: quota_project.map(String::from),
    }
    .into()
}

/// Credentials from a JSON file, dispatching on its `"type"`.
fn credentials_from_file(
    path: &std::path::Path,
    quota_project: Option<&str>,
) -> Result<Credentials> {
    use google_cloud_auth::credentials::{
        external_account, impersonated, service_account, user_account,
    };
    let unauth = |msg: String| {
        Error::new(ErrorKind::Unauthenticated, msg)
            .with_hint("point adc:<file> at a service account key, `gcloud auth application-default login` output, or an external-account config")
    };
    let text = std::fs::read_to_string(path).map_err(|e| {
        unauth(format!(
            "cannot read credentials file {}: {e}",
            path.display()
        ))
    })?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        unauth(format!(
            "credentials file {} is not valid JSON: {e}",
            path.display()
        ))
    })?;
    let kind = json
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    let built = match kind.as_str() {
        "service_account" => {
            let mut b = service_account::Builder::new(json)
                .with_access_specifier(service_account::AccessSpecifier::from_scopes([SCOPE]));
            if let Some(q) = quota_project {
                b = b.with_quota_project_id(q);
            }
            b.build()
        }
        "authorized_user" => {
            let mut b = user_account::Builder::new(json).with_scopes([SCOPE]);
            if let Some(q) = quota_project {
                b = b.with_quota_project_id(q);
            }
            b.build()
        }
        "external_account" => {
            let mut b = external_account::Builder::new(json).with_scopes([SCOPE]);
            if let Some(q) = quota_project {
                b = b.with_quota_project_id(q);
            }
            b.build()
        }
        "impersonated_service_account" => {
            let mut b = impersonated::Builder::new(json).with_scopes([SCOPE]);
            if let Some(q) = quota_project {
                b = b.with_quota_project_id(q);
            }
            b.build()
        }
        other => {
            return Err(Error::invalid(format!(
                "credentials file {} has type {other:?}; expected service_account, authorized_user, external_account or impersonated_service_account",
                path.display()
            )))
        }
    };
    built.map_err(|e| {
        unauth(format!(
            "cannot use credentials file {} ({kind}): {e}",
            path.display()
        ))
    })
}

/// Build credentials for one side.
pub fn build_credentials(spec: &AuthSpec, quota_project: Option<&str>) -> Result<Credentials> {
    match spec {
        AuthSpec::Adc { file: None } => {
            let mut b = credentials::Builder::default().with_scopes([SCOPE]);
            if let Some(q) = quota_project {
                b = b.with_quota_project_id(q);
            }
            b.build().map_err(|e| {
                Error::new(ErrorKind::Unauthenticated, format!("cannot load Application Default Credentials: {e}"))
                    .with_hint("run `gcloud auth application-default login`, set GOOGLE_APPLICATION_CREDENTIALS, or use adc:<file>")
            })
        }
        AuthSpec::Adc { file: Some(path) } => credentials_from_file(path, quota_project),
        AuthSpec::Gcloud { account } => Ok(GcloudToken {
            account: account.clone(),
            quota_project: quota_project.map(String::from),
            cached: Mutex::new(None),
        }
        .into()),
        AuthSpec::Env { var } => {
            let token = std::env::var(var).map_err(|_| {
                Error::new(ErrorKind::Unauthenticated, format!("{var} is not set"))
                    .with_hint(format!("export {var}=$(gcloud auth print-access-token)"))
            })?;
            Ok(static_token_credentials(&token, quota_project))
        }
    }
}

/// Auth headers for a plain `reqwest` call.
pub async fn auth_headers(creds: &Credentials) -> Result<HeaderMap> {
    match creds.headers(Extensions::new()).await {
        Ok(CacheableResource::New { data, .. }) => Ok(data),
        Ok(CacheableResource::NotModified) => Err(Error::internal(
            "credentials returned NotModified without an entity tag",
        )),
        Err(e) => Err(Error::new(
            ErrorKind::Unauthenticated,
            format!("cannot obtain access token: {e}"),
        )
        .with_hint("re-authenticate, e.g. `gcloud auth application-default login`")),
    }
}

/// Email of the authenticated principal, via the OAuth2 tokeninfo endpoint
/// (plain `reqwest`; the SDK has no client for it).
pub async fn whoami(
    http: &reqwest::Client,
    creds: &Credentials,
    tokeninfo_url: &str,
) -> Result<String> {
    let headers = auth_headers(creds).await?;
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| Error::internal("credentials did not produce a bearer token"))?;
    let resp = http
        .post(tokeninfo_url)
        .form(&[("access_token", bearer)])
        .send()
        .await
        .map_err(|e| Error::internal(format!("tokeninfo request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::new(
            ErrorKind::Unauthenticated,
            format!("tokeninfo returned {}", resp.status()),
        ));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| Error::internal(format!("bad tokeninfo response: {e}")))?;
    Ok(v.get("email")
        .and_then(|e| e.as_str())
        .unwrap_or("(unknown principal)")
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn auth_specs_parse_and_round_trip() {
        use std::path::PathBuf;
        let cases = [
            ("adc", AuthSpec::Adc { file: None }),
            (
                "adc:/keys/dest.json",
                AuthSpec::Adc {
                    file: Some(PathBuf::from("/keys/dest.json")),
                },
            ),
            ("gcloud", AuthSpec::Gcloud { account: None }),
            (
                "gcloud:alice@src.example",
                AuthSpec::Gcloud {
                    account: Some("alice@src.example".into()),
                },
            ),
            (
                "env",
                AuthSpec::Env {
                    var: ENV_TOKEN_VAR.into(),
                },
            ),
            (
                "env:DEST_TOKEN",
                AuthSpec::Env {
                    var: "DEST_TOKEN".into(),
                },
            ),
        ];
        for (text, want) in cases {
            let got: AuthSpec = text.parse().unwrap();
            assert_eq!(got, want, "{text}");
            assert_eq!(got.to_string(), text, "round trip");
        }
        // a path may itself contain colons (Windows drive, URLs): only the first splits
        assert_eq!(
            "adc:C:\\keys\\a.json"
                .parse::<AuthSpec>()
                .unwrap()
                .to_string(),
            "adc:C:\\keys\\a.json"
        );
    }

    #[test]
    fn bad_auth_specs_are_usage_errors() {
        for bad in [
            "kerberos",
            "adc:",
            "gcloud:",
            "env:",
            "",
            "ADC",
            "token:abc",
        ] {
            let e = bad.parse::<AuthSpec>().unwrap_err();
            assert_eq!(e.exit_code(), 2, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn credentials_files_dispatch_on_type_and_fail_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            p
        };
        let user = write(
            "user.json",
            r#"{"type":"authorized_user","client_id":"id","client_secret":"s","refresh_token":"r"}"#,
        );
        assert!(build_credentials(&AuthSpec::Adc { file: Some(user) }, Some("quota")).is_ok());

        let unknown = write("odd.json", r#"{"type":"mystery"}"#);
        let e = build_credentials(
            &AuthSpec::Adc {
                file: Some(unknown),
            },
            None,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e.message.contains("mystery") && e.message.contains("service_account"));

        let broken_key = write(
            "sa.json",
            r#"{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com","private_key":"nope","private_key_id":"k","token_uri":"https://oauth2.googleapis.com/token"}"#,
        );
        let e = build_credentials(
            &AuthSpec::Adc {
                file: Some(broken_key),
            },
            None,
        )
        .unwrap_err();
        assert_eq!(
            e.exit_code(),
            3,
            "dispatched to the service-account builder: {}",
            e.message
        );
        assert!(e.message.contains("service_account"));

        let bad_json = write("bad.json", "{ nope");
        assert_eq!(
            build_credentials(
                &AuthSpec::Adc {
                    file: Some(bad_json)
                },
                None
            )
            .unwrap_err()
            .exit_code(),
            3
        );
        let missing = dir.path().join("absent.json");
        let e = build_credentials(
            &AuthSpec::Adc {
                file: Some(missing),
            },
            None,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), 3);
        assert!(e.message.contains("absent.json"));
    }

    #[tokio::test]
    async fn env_specs_read_the_named_variable() {
        std::env::set_var("ORGMOVE_TEST_DEST_TOKEN", "dest-secret");
        let creds =
            build_credentials(&"env:ORGMOVE_TEST_DEST_TOKEN".parse().unwrap(), Some("q")).unwrap();
        std::env::remove_var("ORGMOVE_TEST_DEST_TOKEN");
        let h = auth_headers(&creds).await.unwrap();
        assert_eq!(
            h.get(header::AUTHORIZATION).unwrap().to_str().unwrap(),
            "Bearer dest-secret"
        );
        assert_eq!(h.get(QUOTA_HEADER).unwrap().to_str().unwrap(), "q");
    }

    #[test]
    fn a_missing_variable_is_named_in_the_error() {
        let e = build_credentials(&"env:ORGMOVE_TEST_NOT_SET".parse().unwrap(), None).unwrap_err();
        assert_eq!(e.exit_code(), 3);
        assert!(
            e.message.contains("ORGMOVE_TEST_NOT_SET")
                && e.hint.unwrap().contains("ORGMOVE_TEST_NOT_SET")
        );
    }

    #[tokio::test]
    async fn static_token_builds_bearer_and_quota_headers() {
        let creds: Credentials = StaticToken {
            token: "abc".into(),
            quota_project: Some("billing-proj".into()),
        }
        .into();
        let h = auth_headers(&creds).await.unwrap();
        assert_eq!(
            h.get(header::AUTHORIZATION).unwrap().to_str().unwrap(),
            "Bearer abc"
        );
        assert_eq!(
            h.get(QUOTA_HEADER).unwrap().to_str().unwrap(),
            "billing-proj"
        );
        assert!(h.get(header::AUTHORIZATION).unwrap().is_sensitive());
    }

    #[test]
    fn tokens_are_never_debug_printed() {
        let s = format!(
            "{:?}",
            StaticToken {
                token: "supersecret".into(),
                quota_project: None
            }
        );
        assert!(!s.contains("supersecret"));
    }

    #[test]
    fn env_source_requires_variable() {
        // SAFETY-free: only reads/unsets in this process; name is unique to this tool.
        std::env::remove_var(ENV_TOKEN_VAR);
        let e = build_credentials(
            &AuthSpec::Env {
                var: ENV_TOKEN_VAR.into(),
            },
            None,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), 3);
    }

    #[tokio::test]
    async fn whoami_reads_email_from_tokeninfo() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tokeninfo"))
            .and(body_string_contains("access_token=abc"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"email": "me@example.com"})),
            )
            .mount(&server)
            .await;
        let creds: Credentials = StaticToken {
            token: "abc".into(),
            quota_project: None,
        }
        .into();
        let who = whoami(
            &reqwest::Client::new(),
            &creds,
            &format!("{}/tokeninfo", server.uri()),
        )
        .await
        .unwrap();
        assert_eq!(who, "me@example.com");
    }

    #[tokio::test]
    async fn whoami_maps_rejection_to_unauthenticated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let creds: Credentials = StaticToken {
            token: "bad".into(),
            quota_project: None,
        }
        .into();
        let e = whoami(
            &reqwest::Client::new(),
            &creds,
            &format!("{}/x", server.uri()),
        )
        .await
        .unwrap_err();
        assert_eq!(e.exit_code(), 3);
    }
}
