//! ISE-style authorization policy model and evaluation engine (Phase 2).
//!
//! A policy is an ordered list of **policy sets**; the first set whose `condition`
//! matches the request is selected, then its first matching **rule** wins and its
//! **authorization profile** (Accept/Reject + returned RADIUS attributes) becomes
//! the decision. If no rule in the selected set matches, the `default_profile`
//! applies (implicit Reject otherwise).
//!
//! This module is pure (no I/O, no feature gate) so it is easy to unit-test and to
//! drive from the management API's dry-run endpoint. Wiring the engine into the live
//! request path (enforcement) is a separate step.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

fn default_true() -> bool {
    true
}

/// A RADIUS attribute returned on Accept (e.g. `Tunnel-Private-Group-ID` = `42`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplyAttribute {
    pub name: String,
    pub value: String,
}

/// The terminal effect of an authorization profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Accept,
    Reject,
}

/// A reusable result: accept (with returned attributes) or reject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthzProfile {
    pub id: String,
    pub name: String,
    pub effect: Effect,
    #[serde(default)]
    pub attributes: Vec<ReplyAttribute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_message: Option<String>,
}

/// Comparison operators for a single attribute condition.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    MatchesRegex,
    InCidr,
}

impl Operator {
    /// Evaluate `actual <op> expected`. String compares are case-insensitive
    /// (RADIUS attribute values are commonly compared case-insensitively).
    fn apply(self, actual: &str, expected: &str) -> bool {
        let a = actual.to_lowercase();
        let e = expected.to_lowercase();
        match self {
            Operator::Equals => a == e,
            Operator::NotEquals => a != e,
            Operator::Contains => a.contains(&e),
            Operator::StartsWith => a.starts_with(&e),
            Operator::EndsWith => a.ends_with(&e),
            // Case-insensitive to match the contract of the other operators. An
            // invalid pattern never matches (validate() rejects bad patterns at
            // save time, so this branch is only hit for already-validated regexes).
            Operator::MatchesRegex => regex::RegexBuilder::new(expected)
                .case_insensitive(true)
                .build()
                .map(|re| re.is_match(actual))
                .unwrap_or(false),
            Operator::InCidr => match (
                actual.parse::<IpAddr>(),
                expected.parse::<ipnetwork::IpNetwork>(),
            ) {
                (Ok(ip), Ok(net)) => net.contains(ip),
                _ => false,
            },
        }
    }
}

/// A condition tree evaluated against the request attributes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Logical AND (empty = true).
    All { conditions: Vec<Condition> },
    /// Logical OR (empty = false).
    Any { conditions: Vec<Condition> },
    /// Logical NOT.
    Not { condition: Box<Condition> },
    /// Leaf: compare a request attribute.
    Attr {
        attribute: String,
        operator: Operator,
        value: String,
    },
    /// Always matches (handy for catch-all rules / default policy set).
    Always,
}

impl Condition {
    pub fn always() -> Condition {
        Condition::Always
    }

    /// Validate a condition tree: composite (`all`/`any`) conditions must be
    /// non-empty (an empty `all` is vacuously true — a silent fail-open — and an
    /// empty `any` vacuously false), and every `matches_regex` pattern must compile.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Condition::All { conditions } | Condition::Any { conditions } => {
                if conditions.is_empty() {
                    return Err(
                        "an 'all'/'any' condition must have at least one sub-condition \
                         (use 'always' to match every request)"
                            .to_string(),
                    );
                }
                for c in conditions {
                    c.validate()?;
                }
                Ok(())
            }
            Condition::Not { condition } => condition.validate(),
            Condition::Attr {
                operator: Operator::MatchesRegex,
                value,
                attribute,
            } => regex::Regex::new(value)
                .map(|_| ())
                .map_err(|e| format!("invalid regex for attribute '{attribute}': {e}")),
            Condition::Attr { .. } | Condition::Always => Ok(()),
        }
    }

    /// Does this condition match the request context?
    pub fn matches(&self, ctx: &RequestContext) -> bool {
        match self {
            Condition::All { conditions } => conditions.iter().all(|c| c.matches(ctx)),
            Condition::Any { conditions } => conditions.iter().any(|c| c.matches(ctx)),
            Condition::Not { condition } => !condition.matches(ctx),
            Condition::Always => true,
            Condition::Attr {
                attribute,
                operator,
                value,
            } => match ctx.get(attribute) {
                Some(actual) => operator.apply(actual, value),
                // NotEquals against a missing attribute is vacuously true.
                None => matches!(operator, Operator::NotEquals),
            },
        }
    }
}

/// One authorization rule: when `condition` matches, apply `profile`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub condition: Condition,
    /// id of an `AuthzProfile`.
    pub profile: String,
}

/// An ordered group of rules, gated by the set's own `condition`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicySet {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "Condition::always")]
    pub condition: Condition,
    pub rules: Vec<Rule>,
}

/// A full authorization policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PolicyConfig {
    #[serde(default)]
    pub policy_sets: Vec<PolicySet>,
    #[serde(default)]
    pub authz_profiles: Vec<AuthzProfile>,
    /// Profile id applied when the selected set matches no rule (else implicit Reject).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
}

/// Request attributes the engine evaluates against (e.g. `User-Name`,
/// `NAS-IP-Address`, `NAS-Port-Type`, `Calling-Station-Id`, `EAP-Type`,
/// `identity-group`, ...).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestContext {
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

impl RequestContext {
    pub fn new(attributes: HashMap<String, String>) -> Self {
        Self { attributes }
    }
    fn get(&self, key: &str) -> Option<&String> {
        // Case-insensitive attribute name lookup.
        self.attributes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    }
}

/// The outcome of evaluating a policy against a request.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_set: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default)]
    pub attributes: Vec<ReplyAttribute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_message: Option<String>,
    /// Human-readable trace of why this decision was reached.
    pub reason: String,
}

impl PolicyConfig {
    fn profile(&self, id: &str) -> Option<&AuthzProfile> {
        self.authz_profiles.iter().find(|p| p.id == id)
    }

    /// Validate referential integrity: every rule (and the optional default) must
    /// reference an existing authorization profile, and ids must be unique.
    pub fn validate(&self) -> Result<(), String> {
        let mut profile_ids = std::collections::HashSet::new();
        for p in &self.authz_profiles {
            if !profile_ids.insert(p.id.as_str()) {
                return Err(format!("duplicate authorization profile id '{}'", p.id));
            }
            // Reject returned attributes the server can't encode, so they fail
            // loudly at save time instead of being silently dropped on the wire.
            for a in &p.attributes {
                if !KNOWN_REPLY_ATTRIBUTES.contains(&a.name.as_str()) {
                    return Err(format!(
                        "profile '{}' returns unsupported attribute '{}' (supported: {})",
                        p.id,
                        a.name,
                        KNOWN_REPLY_ATTRIBUTES.join(", ")
                    ));
                }
            }
        }
        if let Some(def) = &self.default_profile
            && !profile_ids.contains(def.as_str())
        {
            return Err(format!("default_profile '{def}' is not a defined profile"));
        }
        let mut set_ids = std::collections::HashSet::new();
        for set in &self.policy_sets {
            if !set_ids.insert(set.id.as_str()) {
                return Err(format!("duplicate policy set id '{}'", set.id));
            }
            set.condition
                .validate()
                .map_err(|e| format!("policy set '{}': {e}", set.id))?;
            let mut rule_ids = std::collections::HashSet::new();
            for rule in &set.rules {
                if !rule_ids.insert(rule.id.as_str()) {
                    return Err(format!(
                        "duplicate rule id '{}' in set '{}'",
                        rule.id, set.id
                    ));
                }
                rule.condition
                    .validate()
                    .map_err(|e| format!("rule '{}' in set '{}': {e}", rule.id, set.id))?;
                if !profile_ids.contains(rule.profile.as_str()) {
                    return Err(format!(
                        "rule '{}' in set '{}' references unknown profile '{}'",
                        rule.id, set.id, rule.profile
                    ));
                }
            }
        }
        Ok(())
    }

    fn decision_from(&self, profile_id: &str, set: Option<&str>, rule: Option<&str>) -> Decision {
        match self.profile(profile_id) {
            Some(p) => Decision {
                effect: p.effect,
                policy_set: set.map(str::to_string),
                rule: rule.map(str::to_string),
                profile: Some(p.id.clone()),
                attributes: p.attributes.clone(),
                reply_message: p.reply_message.clone(),
                reason: match (set, rule) {
                    (Some(s), Some(r)) => format!("set '{s}' rule '{r}' -> profile '{}'", p.name),
                    _ => format!("default profile '{}'", p.name),
                },
            },
            None => Decision::reject(format!("profile '{profile_id}' not found")),
        }
    }

    /// Evaluate this policy against a request context.
    pub fn evaluate(&self, ctx: &RequestContext) -> Decision {
        for set in self.policy_sets.iter().filter(|s| s.enabled) {
            if !set.condition.matches(ctx) {
                continue;
            }
            // First matching set is selected; find the first matching rule.
            for rule in set.rules.iter().filter(|r| r.enabled) {
                if rule.condition.matches(ctx) {
                    return self.decision_from(&rule.profile, Some(&set.name), Some(&rule.name));
                }
            }
            // Selected set matched no rule -> default profile (or implicit reject).
            return match &self.default_profile {
                Some(id) => self.decision_from(id, None, None),
                None => Decision::reject(format!("set '{}' matched no rule", set.name)),
            };
        }
        match &self.default_profile {
            Some(id) => self.decision_from(id, None, None),
            None => Decision::reject("no policy set matched".to_string()),
        }
    }
}

impl Decision {
    fn reject(reason: String) -> Decision {
        Decision {
            effect: Effect::Reject,
            policy_set: None,
            rule: None,
            profile: None,
            attributes: Vec::new(),
            reply_message: None,
            reason,
        }
    }
}

/// A dictionary entry describing an attribute available for conditions (drives the
/// UI's Condition Studio).
#[derive(Debug, Clone, Serialize)]
pub struct DictionaryAttribute {
    pub name: &'static str,
    pub label: &'static str,
    pub description: &'static str,
}

/// Authorization-profile attributes the server knows how to put on the wire.
/// Kept in sync with `policy_enforce::reply_attribute`; `validate()` rejects any
/// profile attribute outside this set so unknown names can't be silently dropped.
pub const KNOWN_REPLY_ATTRIBUTES: &[&str] = &[
    "Filter-Id",
    "Reply-Message",
    "Class",
    "Session-Timeout",
    "Idle-Timeout",
    "Tunnel-Type",
    "Tunnel-Medium-Type",
    "Tunnel-Private-Group-ID",
];

/// What the UI offers when authoring policy: condition attributes + operators, and
/// the reply attributes a profile may return.
#[derive(Debug, Clone, Serialize)]
pub struct Dictionary {
    pub attributes: Vec<DictionaryAttribute>,
    pub operators: Vec<&'static str>,
    pub reply_attributes: Vec<&'static str>,
}

/// Build the policy dictionary. Condition attributes are limited to those the
/// enforcement path actually populates from the request (so the UI can't offer a
/// condition that would silently never match).
pub fn dictionary() -> Dictionary {
    let attr = |name, label, description| DictionaryAttribute {
        name,
        label,
        description,
    };
    Dictionary {
        attributes: vec![
            attr("User-Name", "User name", "RADIUS User-Name"),
            attr(
                "NAS-IP-Address",
                "NAS IP",
                "Network Access Server source IP",
            ),
            attr("NAS-Identifier", "NAS identifier", "RADIUS NAS-Identifier"),
            attr(
                "NAS-Port-Type",
                "NAS port type",
                "e.g. Ethernet, Wireless-802.11",
            ),
            attr(
                "Called-Station-Id",
                "Called-Station-Id",
                "Often the NAS MAC/SSID",
            ),
            attr("Calling-Station-Id", "Calling-Station-Id", "Client MAC"),
            attr("Service-Type", "Service-Type", "e.g. Framed, Login"),
            attr("Framed-Protocol", "Framed-Protocol", "e.g. PPP"),
            attr("EAP-Type", "EAP type", "e.g. EAP-TLS, PEAP, EAP-TEAP"),
            attr("Filter-Id", "Filter-Id", "RADIUS Filter-Id"),
        ],
        operators: vec![
            "equals",
            "not_equals",
            "contains",
            "starts_with",
            "ends_with",
            "matches_regex",
            "in_cidr",
        ],
        reply_attributes: KNOWN_REPLY_ATTRIBUTES.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(pairs: &[(&str, &str)]) -> RequestContext {
        RequestContext::new(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    fn accept(id: &str) -> AuthzProfile {
        AuthzProfile {
            id: id.to_string(),
            name: id.to_string(),
            effect: Effect::Accept,
            attributes: vec![ReplyAttribute {
                name: "Tunnel-Private-Group-ID".into(),
                value: "42".into(),
            }],
            reply_message: None,
        }
    }

    #[test]
    fn operator_equals_is_case_insensitive() {
        assert!(Operator::Equals.apply("Wireless-802.11", "wireless-802.11"));
        assert!(!Operator::Equals.apply("a", "b"));
    }

    #[test]
    fn operator_in_cidr() {
        assert!(Operator::InCidr.apply("10.0.1.5", "10.0.0.0/8"));
        assert!(!Operator::InCidr.apply("192.168.1.5", "10.0.0.0/8"));
    }

    #[test]
    fn missing_attribute_only_matches_not_equals() {
        let c = ctx(&[]);
        let eq = Condition::Attr {
            attribute: "User-Name".into(),
            operator: Operator::Equals,
            value: "x".into(),
        };
        let ne = Condition::Attr {
            attribute: "User-Name".into(),
            operator: Operator::NotEquals,
            value: "x".into(),
        };
        assert!(!eq.matches(&c));
        assert!(ne.matches(&c));
    }

    #[test]
    fn and_or_not_combine() {
        let c = ctx(&[("User-Name", "alice"), ("NAS-Port-Type", "Wireless-802.11")]);
        let cond = Condition::All {
            conditions: vec![
                Condition::Attr {
                    attribute: "User-Name".into(),
                    operator: Operator::Equals,
                    value: "alice".into(),
                },
                Condition::Any {
                    conditions: vec![
                        Condition::Attr {
                            attribute: "NAS-Port-Type".into(),
                            operator: Operator::Equals,
                            value: "Ethernet".into(),
                        },
                        Condition::Attr {
                            attribute: "NAS-Port-Type".into(),
                            operator: Operator::Contains,
                            value: "wireless".into(),
                        },
                    ],
                },
            ],
        };
        assert!(cond.matches(&c));
    }

    #[test]
    fn evaluate_first_matching_set_then_rule() {
        let policy = PolicyConfig {
            authz_profiles: vec![
                accept("vlan-staff"),
                AuthzProfile {
                    id: "deny".into(),
                    name: "deny".into(),
                    effect: Effect::Reject,
                    attributes: vec![],
                    reply_message: Some("nope".into()),
                },
            ],
            default_profile: Some("deny".into()),
            policy_sets: vec![PolicySet {
                id: "wifi".into(),
                name: "Wireless".into(),
                enabled: true,
                condition: Condition::Attr {
                    attribute: "NAS-Port-Type".into(),
                    operator: Operator::Contains,
                    value: "wireless".into(),
                },
                rules: vec![Rule {
                    id: "staff".into(),
                    name: "Staff -> VLAN".into(),
                    enabled: true,
                    condition: Condition::Attr {
                        attribute: "identity-group".into(),
                        operator: Operator::Equals,
                        value: "staff".into(),
                    },
                    profile: "vlan-staff".into(),
                }],
            }],
        };

        let d = policy.evaluate(&ctx(&[
            ("NAS-Port-Type", "Wireless-802.11"),
            ("identity-group", "staff"),
        ]));
        assert_eq!(d.effect, Effect::Accept);
        assert_eq!(d.profile.as_deref(), Some("vlan-staff"));
        assert_eq!(d.attributes.len(), 1);

        // Set matches but rule doesn't -> default profile (reject).
        let d2 = policy.evaluate(&ctx(&[
            ("NAS-Port-Type", "Wireless-802.11"),
            ("identity-group", "guest"),
        ]));
        assert_eq!(d2.effect, Effect::Reject);

        // No set matches -> default profile (reject).
        let d3 = policy.evaluate(&ctx(&[("NAS-Port-Type", "Ethernet")]));
        assert_eq!(d3.effect, Effect::Reject);
    }

    #[test]
    fn regex_operator_is_case_insensitive() {
        let c = Condition::Attr {
            attribute: "User-Name".into(),
            operator: Operator::MatchesRegex,
            value: "^STAFF[0-9]+$".into(),
        };
        assert!(c.matches(&ctx(&[("User-Name", "staff01")])));
    }

    #[test]
    fn validate_rejects_empty_composite_condition() {
        let policy = PolicyConfig {
            authz_profiles: vec![accept("p")],
            default_profile: None,
            policy_sets: vec![PolicySet {
                id: "s".into(),
                name: "s".into(),
                enabled: true,
                condition: Condition::All { conditions: vec![] },
                rules: vec![],
            }],
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_rejects_invalid_regex() {
        let policy = PolicyConfig {
            authz_profiles: vec![accept("p")],
            default_profile: None,
            policy_sets: vec![PolicySet {
                id: "s".into(),
                name: "s".into(),
                enabled: true,
                condition: Condition::Always,
                rules: vec![Rule {
                    id: "r".into(),
                    name: "r".into(),
                    enabled: true,
                    condition: Condition::Attr {
                        attribute: "User-Name".into(),
                        operator: Operator::MatchesRegex,
                        value: "(staff".into(),
                    },
                    profile: "p".into(),
                }],
            }],
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_accepts_well_formed_policy() {
        let policy = PolicyConfig {
            authz_profiles: vec![accept("p")],
            default_profile: Some("p".into()),
            policy_sets: vec![PolicySet {
                id: "s".into(),
                name: "s".into(),
                enabled: true,
                condition: Condition::Always,
                rules: vec![Rule {
                    id: "r".into(),
                    name: "r".into(),
                    enabled: true,
                    condition: Condition::All {
                        conditions: vec![Condition::Attr {
                            attribute: "identity-group".into(),
                            operator: Operator::Equals,
                            value: "staff".into(),
                        }],
                    },
                    profile: "p".into(),
                }],
            }],
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_rejects_unknown_reply_attribute() {
        let policy = PolicyConfig {
            authz_profiles: vec![AuthzProfile {
                id: "p".into(),
                name: "p".into(),
                effect: Effect::Accept,
                attributes: vec![ReplyAttribute {
                    name: "Made-Up-Attr".into(),
                    value: "x".into(),
                }],
                reply_message: None,
            }],
            default_profile: None,
            policy_sets: vec![],
        };
        let err = policy.validate().unwrap_err();
        assert!(err.contains("Made-Up-Attr"), "unexpected error: {err}");
    }

    #[test]
    fn matches_nested_group_with_not() {
        // ALL[ EAP-Type == EAP-TLS, NOT( ANY[ NAS-Port-Type == Async ] ) ] — the
        // shape the recursive UI editor now produces (nested group under a NOT).
        let cond = Condition::All {
            conditions: vec![
                Condition::Attr {
                    attribute: "EAP-Type".into(),
                    operator: Operator::Equals,
                    value: "EAP-TLS".into(),
                },
                Condition::Not {
                    condition: Box::new(Condition::Any {
                        conditions: vec![Condition::Attr {
                            attribute: "NAS-Port-Type".into(),
                            operator: Operator::Equals,
                            value: "Async".into(),
                        }],
                    }),
                },
            ],
        };
        // EAP-TLS over Ethernet → inner ANY is false, NOT(false)=true, ALL=true.
        assert!(cond.matches(&ctx(&[
            ("EAP-Type", "EAP-TLS"),
            ("NAS-Port-Type", "Ethernet")
        ])));
        // EAP-TLS over Async → inner ANY is true, NOT(true)=false, ALL=false.
        assert!(!cond.matches(&ctx(&[("EAP-Type", "EAP-TLS"), ("NAS-Port-Type", "Async")])));
        // Wrong EAP type → first leaf fails, ALL=false.
        assert!(!cond.matches(&ctx(&[("EAP-Type", "PEAP"), ("NAS-Port-Type", "Ethernet")])));
        assert!(cond.validate().is_ok());
    }

    #[test]
    fn empty_policy_rejects() {
        let d = PolicyConfig::default().evaluate(&ctx(&[("User-Name", "x")]));
        assert_eq!(d.effect, Effect::Reject);
    }

    #[test]
    fn round_trips_through_json() {
        let policy = PolicyConfig {
            authz_profiles: vec![accept("p")],
            default_profile: None,
            policy_sets: vec![PolicySet {
                id: "s".into(),
                name: "s".into(),
                enabled: true,
                condition: Condition::Always,
                rules: vec![Rule {
                    id: "r".into(),
                    name: "r".into(),
                    enabled: true,
                    condition: Condition::Always,
                    profile: "p".into(),
                }],
            }],
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: PolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }
}
