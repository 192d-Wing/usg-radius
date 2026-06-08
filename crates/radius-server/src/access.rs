//! AWS-IAM-style ABAC authorization for the management API.
//!
//! An [`AccessPolicy`] is an ordered list of [`Statement`]s, each granting or
//! denying a set of granular `Action`s on a set of `Resource`s, optionally gated
//! by attribute-based [`ConditionEntry`]s. Evaluation follows IAM semantics:
//!
//! * a statement *applies* iff one of its action globs matches the request action
//!   AND one of its resource globs matches the request resource AND **every**
//!   condition entry matches the request [`AccessContext`];
//! * an explicit [`Effect::Deny`] among applicable statements wins;
//! * otherwise any applicable [`Effect::Allow`] grants access;
//! * otherwise the request is **denied by default**.
//!
//! The module is pure (no I/O, no feature gate) so it is easy to unit-test and to
//! reuse from the management API's authorization middleware. ABAC means the
//! decision is driven by *attributes* of the principal (mTLS client certificate
//! and forwarded OIDC identity) and of the request (action, resource, source IP),
//! matched by conditions — not by fixed roles.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Allow or deny — the terminal effect of a [`Statement`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum Effect {
    Allow,
    Deny,
}

/// Condition operators, modeled on the AWS IAM condition operators. String
/// operators compare case-insensitively (consistent with the RADIUS policy
/// engine); `StringLike`/`StringNotLike` additionally honor `*`/`?` wildcards.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum ConditionOp {
    StringEquals,
    StringNotEquals,
    StringLike,
    StringNotLike,
    IpAddress,
    NotIpAddress,
    Bool,
}

/// One condition entry: `<operator>(context[key], values)`.
///
/// When the context holds multiple values for `key` (e.g. several `identity:Group`
/// memberships), the positive operators use **ForAnyValue** semantics — the entry
/// matches if *any* context value satisfies *any* listed value. The negative
/// operators (`StringNotEquals`, `StringNotLike`, `NotIpAddress`) require that *no*
/// context value matches any listed value (so a missing/empty key trivially
/// satisfies a "not" condition, matching IAM behavior).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConditionEntry {
    pub operator: ConditionOp,
    pub key: String,
    pub values: Vec<String>,
}

impl ConditionEntry {
    fn is_negative(&self) -> bool {
        matches!(
            self.operator,
            ConditionOp::StringNotEquals | ConditionOp::StringNotLike | ConditionOp::NotIpAddress
        )
    }

    /// Does a single (context_value, expected_value) pair satisfy this operator?
    fn pair_matches(&self, actual: &str, expected: &str) -> bool {
        match self.operator {
            ConditionOp::StringEquals | ConditionOp::StringNotEquals => {
                actual.eq_ignore_ascii_case(expected)
            }
            ConditionOp::StringLike | ConditionOp::StringNotLike => glob_match(expected, actual),
            ConditionOp::IpAddress | ConditionOp::NotIpAddress => {
                match (
                    actual.parse::<IpAddr>(),
                    expected.parse::<ipnetwork::IpNetwork>(),
                ) {
                    (Ok(ip), Ok(net)) => net.contains(ip),
                    _ => false,
                }
            }
            ConditionOp::Bool => actual.eq_ignore_ascii_case(expected),
        }
    }

    /// Evaluate this condition entry against the context.
    fn matches(&self, ctx: &AccessContext) -> bool {
        let actuals = ctx.get(&self.key);
        if self.is_negative() {
            // "not" conditions: satisfied unless some context value matches a listed
            // value. Empty/missing context key trivially satisfies (IAM semantics).
            !actuals
                .iter()
                .any(|a| self.values.iter().any(|e| self.pair_matches(a, e)))
        } else {
            // Positive (ForAnyValue): some context value matches some listed value.
            actuals
                .iter()
                .any(|a| self.values.iter().any(|e| self.pair_matches(a, e)))
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.values.is_empty() {
            return Err(format!("condition on '{}' has no values", self.key));
        }
        if matches!(
            self.operator,
            ConditionOp::IpAddress | ConditionOp::NotIpAddress
        ) {
            for v in &self.values {
                v.parse::<ipnetwork::IpNetwork>().map_err(|e| {
                    format!("invalid CIDR '{v}' in condition on '{}': {e}", self.key)
                })?;
            }
        }
        Ok(())
    }
}

/// One IAM-style statement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Statement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub effect: Effect,
    /// Action globs, e.g. `radius:GetPolicy`, `radius:Get*`, `radius:*`, `*`.
    pub action: Vec<String>,
    /// Resource globs, e.g. `arn:usgradius:mgmt:::policy`, `arn:usgradius:mgmt:::*`, `*`.
    pub resource: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition: Vec<ConditionEntry>,
}

impl Statement {
    /// Does this statement apply to `(action, resource, ctx)`?
    fn applies(&self, action: &str, resource: &str, ctx: &AccessContext) -> bool {
        self.action.iter().any(|a| glob_match(a, action))
            && self.resource.iter().any(|r| glob_match(r, resource))
            && self.condition.iter().all(|c| c.matches(ctx))
    }

    fn validate(&self) -> Result<(), String> {
        let who = self.sid.as_deref().unwrap_or("<unnamed>");
        if self.action.is_empty() {
            return Err(format!("statement '{who}' has no actions"));
        }
        if self.resource.is_empty() {
            return Err(format!("statement '{who}' has no resources"));
        }
        for c in &self.condition {
            c.validate()
                .map_err(|e| format!("statement '{who}': {e}"))?;
        }
        Ok(())
    }
}

/// A full IAM-style access policy for the management API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AccessPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default)]
    pub statements: Vec<Statement>,
}

/// The outcome of evaluating an [`AccessPolicy`], including the matched statement
/// id and a human-readable reason for the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    pub allowed: bool,
    pub matched_sid: Option<String>,
    pub reason: String,
}

impl AccessPolicy {
    /// Validate the policy: every statement must name ≥1 action and ≥1 resource,
    /// and every IpAddress condition value must be a valid CIDR.
    pub fn validate(&self) -> Result<(), String> {
        for s in &self.statements {
            s.validate()?;
        }
        Ok(())
    }

    /// Evaluate `(action, resource)` against the context with IAM semantics:
    /// explicit Deny wins, else any Allow grants, else default Deny.
    pub fn evaluate(&self, action: &str, resource: &str, ctx: &AccessContext) -> AccessDecision {
        let mut allow_sid: Option<Option<String>> = None;
        for s in &self.statements {
            if !s.applies(action, resource, ctx) {
                continue;
            }
            match s.effect {
                Effect::Deny => {
                    // Explicit deny short-circuits everything.
                    return AccessDecision {
                        allowed: false,
                        matched_sid: s.sid.clone(),
                        reason: format!(
                            "explicit Deny by statement '{}' for {action} on {resource}",
                            s.sid.as_deref().unwrap_or("<unnamed>")
                        ),
                    };
                }
                Effect::Allow => {
                    // Remember the first allow but keep scanning for a later deny.
                    if allow_sid.is_none() {
                        allow_sid = Some(s.sid.clone());
                    }
                }
            }
        }
        match allow_sid {
            Some(sid) => AccessDecision {
                allowed: true,
                matched_sid: sid.clone(),
                reason: format!(
                    "allowed by statement '{}' for {action} on {resource}",
                    sid.as_deref().unwrap_or("<unnamed>")
                ),
            },
            None => AccessDecision {
                allowed: false,
                matched_sid: None,
                reason: format!("implicit Deny (no statement allows {action} on {resource})"),
            },
        }
    }
}

/// Attributes of the principal and request that conditions evaluate against.
/// Multi-valued (a key may hold several values, e.g. group memberships or cert
/// SANs), mirroring IAM's multi-valued condition keys.
#[derive(Debug, Clone, Default)]
pub struct AccessContext {
    values: HashMap<String, Vec<String>>,
}

impl AccessContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a single-valued key (replaces any existing values). No-op if `value`
    /// is `None` or empty, so absent attributes simply don't appear in the context.
    pub fn set(&mut self, key: &str, value: Option<impl Into<String>>) -> &mut Self {
        if let Some(v) = value {
            let v = v.into();
            if !v.is_empty() {
                self.values.insert(key.to_string(), vec![v]);
            }
        }
        self
    }

    /// Set a multi-valued key (empty entries are dropped).
    pub fn set_multi(&mut self, key: &str, values: impl IntoIterator<Item = String>) -> &mut Self {
        let vals: Vec<String> = values.into_iter().filter(|v| !v.is_empty()).collect();
        if !vals.is_empty() {
            self.values.insert(key.to_string(), vals);
        }
        self
    }

    fn get(&self, key: &str) -> &[String] {
        self.values.get(key).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Match `text` against a glob `pattern` supporting `*` (any run, incl. empty) and
/// `?` (exactly one char). Case-insensitive, anchored at both ends. Used for both
/// action/resource matching and `StringLike` conditions. Backtracking is bounded
/// by input length (the patterns are short, operator-authored strings).
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    // Iterative wildcard matcher with O(p*t) worst case and O(1) extra space.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut star_t): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(
        sid: &str,
        actions: &[&str],
        resources: &[&str],
        cond: Vec<ConditionEntry>,
    ) -> Statement {
        Statement {
            sid: Some(sid.into()),
            effect: Effect::Allow,
            action: actions.iter().map(|s| s.to_string()).collect(),
            resource: resources.iter().map(|s| s.to_string()).collect(),
            condition: cond,
        }
    }
    fn deny(
        sid: &str,
        actions: &[&str],
        resources: &[&str],
        cond: Vec<ConditionEntry>,
    ) -> Statement {
        Statement {
            effect: Effect::Deny,
            ..allow(sid, actions, resources, cond)
        }
    }
    fn cond(op: ConditionOp, key: &str, values: &[&str]) -> ConditionEntry {
        ConditionEntry {
            operator: op,
            key: key.into(),
            values: values.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn glob_matches() {
        assert!(glob_match("*", "radius:GetPolicy"));
        assert!(glob_match("radius:*", "radius:GetPolicy"));
        assert!(glob_match("radius:Get*", "radius:GetPolicy"));
        assert!(!glob_match("radius:Get*", "radius:PutPolicy"));
        assert!(glob_match("radius:?etPolicy", "radius:GetPolicy"));
        assert!(glob_match(
            "arn:usgradius:mgmt:::*",
            "arn:usgradius:mgmt:::policy"
        ));
        assert!(!glob_match("radius:GetPolicy", "radius:GetPolicyExtra"));
    }

    #[test]
    fn default_deny_when_no_statement_matches() {
        let p = AccessPolicy {
            version: None,
            statements: vec![allow("s", &["radius:GetPolicy"], &["*"], vec![])],
        };
        let d = p.evaluate(
            "radius:PutPolicy",
            "arn:usgradius:mgmt:::policy",
            &AccessContext::new(),
        );
        assert!(!d.allowed);
        assert!(d.reason.contains("implicit Deny"));
    }

    #[test]
    fn allow_then_explicit_deny_wins() {
        let p = AccessPolicy {
            version: None,
            statements: vec![
                allow("broad", &["radius:*"], &["*"], vec![]),
                deny(
                    "guard",
                    &["radius:PutPolicy"],
                    &["*"],
                    vec![cond(
                        ConditionOp::NotIpAddress,
                        "request:SourceIp",
                        &["10.0.0.0/8"],
                    )],
                ),
            ],
        };
        // PutPolicy from outside the admin CIDR → guard's NotIpAddress matches → Deny.
        let mut outside = AccessContext::new();
        outside.set("request:SourceIp", Some("192.0.2.5"));
        let d = p.evaluate("radius:PutPolicy", "arn:usgradius:mgmt:::policy", &outside);
        assert!(!d.allowed, "{}", d.reason);
        assert_eq!(d.matched_sid.as_deref(), Some("guard"));

        // PutPolicy from inside the CIDR → guard does not apply → broad Allow wins.
        let mut inside = AccessContext::new();
        inside.set("request:SourceIp", Some("10.1.2.3"));
        let d = p.evaluate("radius:PutPolicy", "arn:usgradius:mgmt:::policy", &inside);
        assert!(d.allowed, "{}", d.reason);
        assert_eq!(d.matched_sid.as_deref(), Some("broad"));
    }

    #[test]
    fn group_membership_for_any_value() {
        let p = AccessPolicy {
            version: None,
            statements: vec![allow(
                "ops",
                &["radius:Get*", "radius:List*"],
                &["*"],
                vec![cond(
                    ConditionOp::StringEquals,
                    "identity:Group",
                    &["operators", "policy-admins"],
                )],
            )],
        };
        let mut ctx = AccessContext::new();
        ctx.set_multi("identity:Group", ["staff".into(), "operators".into()]);
        // A user in 'operators' (one of several groups) can GetStatus.
        assert!(
            p.evaluate("radius:GetStatus", "arn:usgradius:mgmt:::status", &ctx)
                .allowed
        );
        // But not PutPolicy (action not granted).
        assert!(
            !p.evaluate("radius:PutPolicy", "arn:usgradius:mgmt:::policy", &ctx)
                .allowed
        );
        // A user with no matching group is denied.
        let mut other = AccessContext::new();
        other.set_multi("identity:Group", ["interns".into()]);
        assert!(
            !p.evaluate("radius:GetStatus", "arn:usgradius:mgmt:::status", &other)
                .allowed
        );
    }

    #[test]
    fn string_like_on_cert_cn() {
        let p = AccessPolicy {
            version: None,
            statements: vec![allow(
                "bff",
                &["radius:*"],
                &["*"],
                vec![cond(
                    ConditionOp::StringLike,
                    "tls:ClientCN",
                    &["usg-radius-bff.*"],
                )],
            )],
        };
        let mut ctx = AccessContext::new();
        ctx.set("tls:ClientCN", Some("usg-radius-bff.radius.svc"));
        assert!(
            p.evaluate("radius:GetPolicy", "arn:usgradius:mgmt:::policy", &ctx)
                .allowed
        );
        let mut other = AccessContext::new();
        other.set("tls:ClientCN", Some("attacker.example"));
        assert!(
            !p.evaluate("radius:GetPolicy", "arn:usgradius:mgmt:::policy", &other)
                .allowed
        );
    }

    #[test]
    fn negative_condition_satisfied_when_key_absent() {
        // NotIpAddress with no SourceIp in context → condition trivially satisfied.
        let c = cond(
            ConditionOp::NotIpAddress,
            "request:SourceIp",
            &["10.0.0.0/8"],
        );
        assert!(c.matches(&AccessContext::new()));
    }

    #[test]
    fn example_policy_parses_and_enforces() {
        // The shipped example must always parse, validate, and behave as documented.
        let raw = include_str!("../../../examples/configs/access-policy.example.json");
        let pol: AccessPolicy = serde_json::from_str(raw).expect("example policy parses");
        pol.validate().expect("example policy validates");

        // An operator can read policy.
        let mut op = AccessContext::new();
        op.set_multi("identity:Group", ["operators".into()]);
        assert!(p_allows(&pol, "radius:GetPolicy", &op));

        // A policy-admin from the internal network can PUT.
        let mut admin_internal = AccessContext::new();
        admin_internal.set_multi("identity:Group", ["policy-admins".into()]);
        admin_internal.set("request:SourceIp", Some("10.4.5.6"));
        assert!(p_allows(&pol, "radius:PutPolicy", &admin_internal));

        // A policy-admin from OUTSIDE is explicitly denied (the Deny statement wins).
        let mut admin_external = AccessContext::new();
        admin_external.set_multi("identity:Group", ["policy-admins".into()]);
        admin_external.set("request:SourceIp", Some("203.0.113.7"));
        assert!(!p_allows(&pol, "radius:PutPolicy", &admin_external));

        // The trusted BFF cert identity can read but not PUT.
        let mut bff = AccessContext::new();
        bff.set("tls:ClientCN", Some("usg-radius-bff.radius.svc"));
        assert!(p_allows(&pol, "radius:GetStatus", &bff));
        assert!(!p_allows(&pol, "radius:PutPolicy", &bff));
    }

    fn p_allows(p: &AccessPolicy, action: &str, ctx: &AccessContext) -> bool {
        let resource = if action.ends_with("Policy") {
            "arn:usgradius:mgmt:::policy"
        } else {
            "arn:usgradius:mgmt:::status"
        };
        p.evaluate(action, resource, ctx).allowed
    }

    #[test]
    fn validate_rejects_bad_cidr_and_empty() {
        let p = AccessPolicy {
            version: None,
            statements: vec![allow(
                "bad",
                &["radius:*"],
                &["*"],
                vec![cond(
                    ConditionOp::IpAddress,
                    "request:SourceIp",
                    &["not-a-cidr"],
                )],
            )],
        };
        assert!(p.validate().is_err());

        let empty_action = AccessPolicy {
            version: None,
            statements: vec![allow("noaction", &[], &["*"], vec![])],
        };
        assert!(empty_action.validate().is_err());
    }
}
