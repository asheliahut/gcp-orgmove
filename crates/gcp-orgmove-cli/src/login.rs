//! Which login talks to which organization.
//!
//! `--token-source` is the default for both; `--source-auth` and
//! `--destination-auth` override one side. If the two sides end up with the
//! same spec and quota project there is a single login and nothing is routed.

use std::path::Path;

use gcp_orgmove_core::{Manifest, Resource, Result};
use gcp_orgmove_gcp::auth::{self, AuthSpec};
use gcp_orgmove_gcp::real::{Config, RealGcp, Side, SideConfig};
use google_cloud_auth::credentials::Credentials;

use crate::cli::{Command, Global};

/// The resolved (spec, quota project) of each side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub source: (AuthSpec, Option<String>),
    pub destination: (AuthSpec, Option<String>),
    pub move_side: Side,
}

impl Plan {
    pub fn is_split(&self) -> bool {
        self.source != self.destination
    }

    pub fn describe(&self) -> String {
        let one = |(spec, q): &(AuthSpec, Option<String>)| match q {
            Some(q) => format!("{spec} (quota project {q})"),
            None => spec.to_string(),
        };
        if self.is_split() {
            format!(
                "source login: {}; destination login: {}; moves performed as the {} login",
                one(&self.source),
                one(&self.destination),
                self.move_side.name()
            )
        } else {
            format!("one login for both organizations: {}", one(&self.source))
        }
    }
}

/// Work out each side's login from the flags. Pure: reads no credentials.
pub fn resolve(g: &Global) -> Result<Plan> {
    let default: AuthSpec = g.token_source.parse()?;
    let side =
        |explicit: &Option<String>, quota: &Option<String>| -> Result<(AuthSpec, Option<String>)> {
            let spec = match explicit {
                Some(s) => s.parse()?,
                None => default.clone(),
            };
            Ok((spec, quota.clone().or_else(|| g.quota_project.clone())))
        };
    Ok(Plan {
        source: side(&g.source_auth, &g.source_quota_project)?,
        destination: side(&g.destination_auth, &g.destination_quota_project)?,
        move_side: g.move_as.parse()?,
    })
}

pub struct Logins {
    pub plan: Plan,
    pub gcp: RealGcp,
    pub source: Credentials,
    /// `None` when both organizations share the source login.
    pub destination: Option<Credentials>,
}

/// Load the credentials and build the client. Fails with exit 3 (and names the
/// missing variable or file) when a login can't be loaded.
pub fn build(g: &Global) -> Result<Logins> {
    let plan = resolve(g)?;
    let source = auth::build_credentials(&plan.source.0, plan.source.1.as_deref())?;
    let destination = if plan.is_split() {
        Some(auth::build_credentials(
            &plan.destination.0,
            plan.destination.1.as_deref(),
        )?)
    } else {
        None
    };
    let gcp = RealGcp::new(Config {
        source: SideConfig {
            credentials: source.clone(),
            endpoint: None,
        },
        destination: destination.clone().map(|credentials| SideConfig {
            credentials,
            endpoint: None,
        }),
        move_side: plan.move_side,
        concurrency: usize::from(g.concurrency),
        identity_backoff: Default::default(),
    });
    Ok(Logins {
        plan,
        gcp,
        source,
        destination,
    })
}

impl Logins {
    /// Who we are, for `init`: one principal, or both when the logins differ.
    pub async fn whoami(&self, http: &reqwest::Client, tokeninfo_url: &str) -> Result<String> {
        let src = auth::whoami(http, &self.source, tokeninfo_url).await?;
        match &self.destination {
            None => Ok(src),
            Some(d) => {
                let dst = auth::whoami(http, d, tokeninfo_url).await?;
                Ok(format!("{src} (source), {dst} (destination)"))
            }
        }
    }
}

/// Tell the router which login owns what, from what we already know, so the
/// first call goes to the right place. Best effort: a missing or invalid
/// manifest just means routing learns as it goes.
pub fn seed_hints(gcp: &RealGcp, cmd: &Command, manifest_path: &Path) {
    if let Command::Init {
        source_org,
        destination_org,
        ..
    } = cmd
    {
        if let Some(Ok(o)) = source_org.as_deref().map(str::parse) {
            gcp.hint_org(&o, Side::Source);
        }
        if let Some(Ok(o)) = destination_org.as_deref().map(str::parse) {
            gcp.hint_org(&o, Side::Destination);
        }
        return;
    }
    let Ok(text) = std::fs::read_to_string(manifest_path) else {
        return;
    };
    let Ok(loaded) = Manifest::parse(&text) else {
        return;
    };
    let m = loaded.manifest;
    gcp.hint_org(&m.source_org, Side::Source);
    gcp.hint_org(&m.destination_org, Side::Destination);
    let landing = m.default_destination_folder.iter().chain(
        m.projects
            .iter()
            .filter_map(|p| p.destination_folder.as_ref()),
    );
    for f in landing {
        gcp.hint(&Resource::Folder(f.clone()), Side::Destination);
    }
    for f in &m.selection.source_folders {
        gcp.hint(&Resource::Folder(f.clone()), Side::Source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    fn global(args: &[&str]) -> Global {
        let mut argv = vec!["gcp-orgmove"];
        argv.extend_from_slice(args);
        argv.push("status");
        Cli::try_parse_from(argv).unwrap().global
    }

    fn spec(s: &str) -> AuthSpec {
        s.parse().unwrap()
    }

    #[test]
    fn defaults_to_one_login_for_both_sides() {
        let p = resolve(&global(&[])).unwrap();
        assert_eq!(p.source, (spec("adc"), None));
        assert!(!p.is_split());
        assert_eq!(p.move_side, Side::Source);
        assert!(p.describe().starts_with("one login for both organizations"));
    }

    #[test]
    fn token_source_applies_to_both_and_each_side_can_override() {
        let p = resolve(&global(&["--token-source", "gcloud"])).unwrap();
        assert_eq!(
            (p.source.0.clone(), p.destination.0.clone()),
            (spec("gcloud"), spec("gcloud"))
        );
        assert!(!p.is_split());

        let p = resolve(&global(&[
            "--source-auth",
            "gcloud:alice@src.example",
            "--destination-auth",
            "adc:/keys/dest.json",
        ]))
        .unwrap();
        assert_eq!(p.source.0, spec("gcloud:alice@src.example"));
        assert_eq!(p.destination.0, spec("adc:/keys/dest.json"));
        assert!(p.is_split());
        assert!(p
            .describe()
            .contains("source login: gcloud:alice@src.example"));
    }

    #[test]
    fn overriding_one_side_leaves_the_other_on_the_default() {
        let p = resolve(&global(&[
            "--token-source",
            "env",
            "--destination-auth",
            "env:DEST_TOKEN",
        ]))
        .unwrap();
        assert_eq!(p.source.0, spec("env"));
        assert_eq!(p.destination.0, spec("env:DEST_TOKEN"));
        assert!(p.is_split());
    }

    #[test]
    fn quota_projects_fall_back_per_side() {
        let p = resolve(&global(&[
            "--quota-project",
            "shared",
            "--destination-quota-project",
            "dest-q",
        ]))
        .unwrap();
        assert_eq!(p.source.1.as_deref(), Some("shared"));
        assert_eq!(p.destination.1.as_deref(), Some("dest-q"));
        assert!(
            p.is_split(),
            "same login but different quota projects still needs two credentials"
        );
        assert!(p.describe().contains("quota project dest-q"));
    }

    #[test]
    fn identical_explicit_specs_are_still_one_login() {
        let p = resolve(&global(&[
            "--source-auth",
            "gcloud:a@x.com",
            "--destination-auth",
            "gcloud:a@x.com",
        ]))
        .unwrap();
        assert!(!p.is_split());
    }

    #[test]
    fn move_as_is_validated_and_bad_specs_are_usage_errors() {
        assert_eq!(
            resolve(&global(&["--move-as", "destination"]))
                .unwrap()
                .move_side,
            Side::Destination
        );
        assert!(Cli::try_parse_from(["gcp-orgmove", "--move-as", "both", "status"]).is_err());
        for flag in ["--token-source", "--source-auth", "--destination-auth"] {
            let e = resolve(&global(&[flag, "kerberos"])).unwrap_err();
            assert_eq!(e.exit_code(), 2, "{flag}");
        }
    }
}
