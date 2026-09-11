//! What a visitor — a hosted caller without an account — may bring.
//!
//! The hosted inspector lets strangers read what the operator pre-wired and
//! refuses to dial an address they chose: an outbound dialer on a public
//! origin, driveable by anyone, is someone else's proxy. A platform that
//! points its own gateways at the inspector needs one exception to that,
//! and this module is its whole shape: the operator lists the URL forms its
//! gateways take, and a visitor may inspect a server whose URL matches one
//! of them. The list is the trust decision; nothing a visitor sends widens
//! it.

use crate::engine::target::{TargetKind, TargetSpec};

/// One operator-listed URL form, e.g. `https://*.mcpg.cloud/mcp`.
///
/// `*` stands for exactly one host label, so `*.mcpg.cloud` admits
/// `acme.mcpg.cloud` and neither `mcpg.cloud` nor `a.b.mcpg.cloud`. Scheme,
/// port and path match exactly; a candidate carrying userinfo, a query or a
/// fragment never matches, whatever the pattern says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlPattern {
    scheme: String,
    host: Vec<Label>,
    port: Option<u16>,
    path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Label {
    Any,
    Literal(String),
}

impl UrlPattern {
    pub fn parse(pattern: &str) -> Result<Self, String> {
        let url = url::Url::parse(pattern.trim())
            .map_err(|e| format!("visitor target pattern {pattern:?} is not a URL: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!(
                "visitor target pattern {pattern:?} must be http or https"
            ));
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(format!(
                "visitor target pattern {pattern:?} may not carry userinfo, a query or a fragment"
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| format!("visitor target pattern {pattern:?} has no host"))?;
        let host = host
            .split('.')
            .map(|label| match label {
                "*" => Ok(Label::Any),
                "" => Err(format!(
                    "visitor target pattern {pattern:?} has an empty host label"
                )),
                l if l.contains('*') => Err(format!(
                    "visitor target pattern {pattern:?}: `*` must stand for a whole host label"
                )),
                l => Ok(Label::Literal(l.to_ascii_lowercase())),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            scheme: url.scheme().to_owned(),
            host,
            port: url.port_or_known_default(),
            path: url.path().to_owned(),
        })
    }

    pub fn matches(&self, candidate: &str) -> bool {
        let Ok(url) = url::Url::parse(candidate) else {
            return false;
        };
        if url.scheme() != self.scheme
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port_or_known_default() != self.port
            || url.path() != self.path
        {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        let labels: Vec<&str> = host.split('.').collect();
        labels.len() == self.host.len()
            && labels.iter().zip(&self.host).all(|(got, want)| match want {
                Label::Any => !got.is_empty(),
                Label::Literal(l) => got.eq_ignore_ascii_case(l),
            })
    }
}

/// The spec a visitor's target is registered with, when its URL is admitted.
///
/// Everything but the URL and the display name is dropped rather than
/// validated: a visitor's workspace is private, so a credential would only
/// ever reach the platform's own edge, but the service holding a stranger's
/// credential at all is a property hosted mode does not have and this path
/// does not add. Signing in is how a caller brings their own.
pub fn admitted(spec: &TargetSpec, patterns: &[UrlPattern]) -> Option<TargetSpec> {
    let TargetKind::Http { url } = &spec.kind else {
        return None;
    };
    if !patterns.iter().any(|p| p.matches(url)) {
        return None;
    }
    let mut admitted: TargetSpec =
        serde_json::from_value(serde_json::json!({ "url": url })).expect("a url is a target");
    admitted.name = spec.name.clone();
    Some(admitted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(s: &str) -> UrlPattern {
        UrlPattern::parse(s).unwrap()
    }

    #[test]
    fn a_wildcard_stands_for_exactly_one_label() {
        let p = pattern("https://*.mcpg.cloud/mcp");
        assert!(p.matches("https://acme.mcpg.cloud/mcp"));
        assert!(p.matches("https://ACME.mcpg.cloud/mcp"));
        assert!(
            !p.matches("https://mcpg.cloud/mcp"),
            "the apex is not a tenant"
        );
        assert!(
            !p.matches("https://a.b.mcpg.cloud/mcp"),
            "a wildcard must not span labels"
        );
        assert!(!p.matches("https://acme.mcpg.cloud.evil.example/mcp"));
    }

    #[test]
    fn scheme_port_and_path_match_exactly() {
        let p = pattern("https://*.mcpg.cloud/mcp");
        assert!(!p.matches("http://acme.mcpg.cloud/mcp"));
        assert!(!p.matches("https://acme.mcpg.cloud:8443/mcp"));
        assert!(!p.matches("https://acme.mcpg.cloud/mcp/"));
        assert!(!p.matches("https://acme.mcpg.cloud/"));
        assert!(!p.matches("https://acme.mcpg.cloud/mcp/../admin"));
        // The known default port and its explicit spelling are one port.
        assert!(p.matches("https://acme.mcpg.cloud:443/mcp"));
    }

    /// The parts of a URL that can smuggle a different destination past a
    /// host comparison never match, whatever the pattern says.
    #[test]
    fn userinfo_query_and_fragment_never_match() {
        let p = pattern("https://*.mcpg.cloud/mcp");
        assert!(!p.matches("https://acme.mcpg.cloud@evil.example/mcp"));
        assert!(!p.matches("https://user:pw@acme.mcpg.cloud/mcp"));
        assert!(!p.matches("https://acme.mcpg.cloud/mcp?x=1"));
        assert!(!p.matches("https://acme.mcpg.cloud/mcp#frag"));
        assert!(!p.matches("not a url"));
        assert!(!p.matches("stdio:sh"));
    }

    #[test]
    fn a_literal_pattern_admits_only_itself() {
        let p = pattern("http://demo.example:7846/mcp");
        assert!(p.matches("http://demo.example:7846/mcp"));
        assert!(!p.matches("http://demo.example/mcp"));
        assert!(!p.matches("http://other.example:7846/mcp"));
    }

    #[test]
    fn malformed_patterns_are_refused_at_parse_time() {
        for bad in [
            "https://mcpg.cloud/mcp?x=1",
            "https://user@mcpg.cloud/mcp",
            "https://a*.mcpg.cloud/mcp",
            "ftp://*.mcpg.cloud/mcp",
            "https://*..cloud/mcp",
            "*.mcpg.cloud/mcp",
            "",
        ] {
            assert!(UrlPattern::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn an_admitted_spec_keeps_only_the_url_and_name() {
        let patterns = [pattern("https://*.mcpg.cloud/mcp")];
        let spec: TargetSpec = serde_json::from_value(serde_json::json!({
            "name": "acme",
            "url": "https://acme.mcpg.cloud/mcp",
            "bearer": "secret",
            "headers": { "X-Api-Key": "k" },
            "allow_private": true,
            "timeout_ms": 1,
        }))
        .unwrap();
        let got = admitted(&spec, &patterns).expect("the URL matches");
        assert_eq!(got.name.as_deref(), Some("acme"));
        assert!(
            matches!(&got.kind, TargetKind::Http { url } if url == "https://acme.mcpg.cloud/mcp")
        );
        assert_eq!(got.bearer, None);
        assert!(got.headers.is_empty());
        assert!(got.aauth.is_none());
        assert_eq!(
            got.timeout_ms, 30_000,
            "a visitor does not choose the timeout"
        );
    }

    #[test]
    fn nothing_is_admitted_without_a_match_or_without_patterns() {
        let patterns = [pattern("https://*.mcpg.cloud/mcp")];
        let spec: TargetSpec =
            serde_json::from_value(serde_json::json!({ "url": "https://example.com/mcp" }))
                .unwrap();
        assert!(admitted(&spec, &patterns).is_none());
        let tenant: TargetSpec =
            serde_json::from_value(serde_json::json!({ "url": "https://acme.mcpg.cloud/mcp" }))
                .unwrap();
        assert!(
            admitted(&tenant, &[]).is_none(),
            "an empty list admits nothing"
        );
        let stdio: TargetSpec =
            serde_json::from_value(serde_json::json!({ "command": "sh" })).unwrap();
        assert!(admitted(&stdio, &patterns).is_none());
    }
}
