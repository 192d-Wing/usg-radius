# Management API Authentication (mTLS + IAM-style ABAC)

The management API (`/api/v1/*`) exposes server state and, critically,
**`PUT /api/v1/policy`**, which rewrites the authorization policy enforced on every
Access-Accept. This page describes how to lock it down with **mutual TLS** for
transport authentication and an **AWS-IAM-style, attribute-based (ABAC) access
policy** for fine-grained authorization.

> **Opt-in.** With no `mgmt` config block the management API stays open (and logs a
> prominent startup warning). Authorization is enforced only once you configure
> `mgmt.access_policy_file`; mTLS is enforced once you configure `mgmt.tls`.

## How it fits together

```
Browser ──OIDC──> oauth2-proxy ──X-Auth-Request-*──> BFF ──mTLS + headers──> mgmt API
```

* **mTLS** authenticates the *channel* — the calling service (typically the UI's
  BFF) presents a client certificate verified against a configured CA.
* The BFF forwards the **oauth2-proxy / Keycloak identity** (`X-Auth-Request-User`,
  `-Email`, `-Groups`). These headers are honored **only over a verified mTLS
  channel** (or if you explicitly opt in), so they can't be spoofed.
* The mgmt API maps the request to a granular **action + resource**, builds an ABAC
  **context** from the cert and identity, and evaluates the **access policy**.

## Configuration

Add an `mgmt` block to `config.json`:

```json
{
  "mgmt": {
    "tls": {
      "cert_path": "/etc/radius/mgmt/server.pem",
      "key_path": "/etc/radius/mgmt/server-key.pem",
      "client_ca_path": "/etc/radius/mgmt/client-ca.pem"
    },
    "access_policy_file": "/etc/radius/access-policy.json",
    "trust_forwarded_identity": true
  }
}
```

* `tls.client_ca_path` **present** ⇒ client certificates are **required** and
  verified (true mTLS). Absent ⇒ server-only TLS.
* `access_policy_file` set ⇒ **authorization is enforced** (default deny).
* `trust_forwarded_identity` (default `true`): honor the forwarded OIDC headers.
  They are still only trusted when a client cert authenticated the peer — set this
  `false` to require the human identity to come *only* over mTLS.

A configured-but-unreadable/invalid access policy file is **fatal at startup** (the
server refuses to run rather than enforce a partially-parsed policy).

### Hot-reload (SIGHUP)

The access policy can be reloaded from disk **without restarting** the server by
sending it `SIGHUP` (Unix):

```sh
kill -HUP "$(pidof usg-radius)"     # or: kubectl exec … -- kill -HUP 1
```

The file is re-read, parsed, and validated **before** swapping. If the new file is
unreadable or invalid the **currently-enforced policy is kept** and an error is
logged — a bad edit can never disable authorization or fail open. Typical flow:
update the mounted ConfigMap, then signal the pod.

## Access policy schema

An access policy is a list of statements evaluated with IAM semantics:

* a statement **applies** when one of its `action` globs matches **and** one of its
  `resource` globs matches **and** *every* `condition` entry matches;
* an explicit **`Deny`** among applicable statements **wins**;
* otherwise any applicable **`Allow`** grants access;
* otherwise the request is **denied by default**.

```json
{
  "version": "2025-06-08",
  "statements": [
    {
      "sid": "AllowOperatorsRead",
      "effect": "Allow",
      "action": ["radius:Get*", "radius:List*", "radius:SimulatePolicy"],
      "resource": ["arn:usgradius:mgmt:::*"],
      "condition": [
        { "operator": "StringEquals", "key": "identity:Group", "values": ["operators"] }
      ]
    },
    {
      "sid": "DenyPolicyEditsOutsideInternalNetwork",
      "effect": "Deny",
      "action": ["radius:PutPolicy"],
      "resource": ["arn:usgradius:mgmt:::policy"],
      "condition": [
        { "operator": "NotIpAddress", "key": "request:SourceIp", "values": ["10.0.0.0/8"] }
      ]
    }
  ]
}
```

A complete, worked example ships at
[`examples/configs/access-policy.example.json`](https://github.com/192d-Wing/usg-radius/blob/main/examples/configs/access-policy.example.json).

### Actions and resources

| HTTP | Action | Resource |
|---|---|---|
| `GET /api/v1/status` | `radius:GetStatus` | `arn:usgradius:mgmt:::status` |
| `GET /api/v1/clients` | `radius:ListClients` | `arn:usgradius:mgmt:::clients` |
| `GET /api/v1/users` | `radius:ListUsers` | `arn:usgradius:mgmt:::users` |
| `GET /api/v1/sessions` | `radius:ListSessions` | `arn:usgradius:mgmt:::sessions` |
| `GET /api/v1/dictionary` | `radius:GetDictionary` | `arn:usgradius:mgmt:::dictionary` |
| `GET /api/v1/policy` | `radius:GetPolicy` | `arn:usgradius:mgmt:::policy` |
| `PUT /api/v1/policy` | `radius:PutPolicy` | `arn:usgradius:mgmt:::policy` |
| `POST /api/v1/policy/dry-run` | `radius:SimulatePolicy` | `arn:usgradius:mgmt:::policy` |

Action and resource matching support `*` and `?` wildcards (e.g. `radius:*`,
`radius:Get*`, `arn:usgradius:mgmt:::*`).

### Condition operators

`StringEquals`, `StringNotEquals`, `StringLike`/`StringNotLike` (with `*`/`?`),
`IpAddress`/`NotIpAddress` (CIDR), and `Bool`. String comparisons are
case-insensitive. When a context key is multi-valued (e.g. group memberships), a
positive operator matches if **any** value matches; a negative operator requires
that **none** match.

### Condition keys

| Key | Source |
|---|---|
| `tls:ClientCN`, `tls:ClientOU` | client certificate subject |
| `tls:ClientSAN` (multi) | client certificate SANs |
| `tls:Fingerprint` | SHA-256 of the client certificate |
| `identity:User`, `identity:Email` | forwarded OIDC headers |
| `identity:Group` (multi) | forwarded OIDC groups |
| `request:Action`, `request:Resource`, `request:Method` | the request |
| `request:SourceIp` | the peer address |

## BFF: presenting a client certificate

By default the BFF talks plain HTTP to the mgmt API (no TLS backend, to keep the
musl image small) and relies on the service mesh for transport security. To have the
BFF present a client certificate itself, build it with the `mtls` feature and set:

```
RADIUS_API_CLIENT_CERT=/etc/bff/client.pem
RADIUS_API_CLIENT_KEY=/etc/bff/client-key.pem
RADIUS_API_CA=/etc/bff/mgmt-ca.pem   # optional: trust the mgmt server cert
```

```sh
cargo build -p radius-ui-bff --features mtls
```

Alternatively, terminate mTLS at a service mesh (e.g. Cilium) and leave the BFF on
plain HTTP.

## Auditing

Authorization denials are logged at `WARN` and written to the JSON audit log
(`audit_log_path`) as `UnauthorizedClient` events, including the principal, action,
resource, and the reason (which statement denied, or implicit default-deny).

## Verify

1. With no `mgmt` block, the server logs `management API is UNAUTHENTICATED …`.
2. With `mgmt.tls.client_ca_path` set, a request **without** a client cert is refused
   at the TLS layer.
3. With a valid client cert and `X-Auth-Request-Groups: operators`,
   `GET /api/v1/policy` returns `200` but `PUT /api/v1/policy` returns `403`.
4. With `X-Auth-Request-Groups: policy-admins` from an allowed source CIDR,
   `PUT /api/v1/policy` returns `200`; from outside the CIDR it returns `403` and an
   audit entry is written.
