# connection-v1

Lane A. Normative for the control plane and for review of K1 and K3.
User decisions in journal §21.1 are binding. Providers are `claude`, `codex`,
and `grok`. `jekko` is `provider_unknown` and is not a managed provider.

Identifiers use the runner `validate_id` rules: 1 to 128 bytes, ASCII
alphanumeric plus `._:/-`, must start and end alphanumeric, and must not
contain `..` or `//`. `owner_id` is an identifier that starts with `user/`
or `service/`. That prefix is the owner kind on the lease without a second
field. A user id and a service-account id must not be equal.

No schema in this contract has a refresh token, an API key, or an access
token property. Logs carry the error code, `connection_id`, generation,
`session_id`, and upstream host. They do not carry credentials, Authorization
values, token responses, or canary bytes.

## 1. Vault record

A connection is owned by one `(owner_kind, owner_id, provider, provider_account)`.
`provider_account` is a public label, not a secret. States are `pending`,
`connected`, and `disconnected`.

`credential_kind` is `oauth_refresh` or `api_key` and stays in the vault.
It is not a lease field. Both kinds use the gateway. An API key is not a
reason to put that key in the guest.

Scheduled, repair, and redteam work name a `connection_id` chosen for that
service account. They do not reuse the interactive user's last login.
A mismatch of owner id, owner prefix, or connection id is
`connection_owner_mismatch`. There is no operator-account fallback and no
fallback to another provider or another credential kind.

## 2. Delivery mode

The lease binding mode is `gateway_helper` or `qualified_ram_token`.

Lane R's uncommitted draft (`ConnectionMode::Subscription` and `ApiKey` in
`jeryu-runner-protocol` `wire/v2/connection.rs`, described in
`managed-session-v2.1.md`) must not ship. Billing and credential kind are
already covered by section 1. The lease mode has to say how bytes reach the
provider, which is the §21.1 decision.

`gateway_helper` is the default and the only mode that is enabled before
qualification. The guest has no NIC. The pinned CLI uses base URL
`http://127.0.0.1:1025` and a non-secret placeholder
(`Bearer jeryu-placeholder`). guestd binds that loopback port, strips
Authorization and any API-key header, and dials host vsock port 1025.
The agent itself must not dial vsock. The node checks the signed lease and
sends the capability to the control-plane gateway over mTLS. The gateway
adds the vault credential.

A guest request that still contains Authorization or an API-key header in
`gateway_helper` mode is rejected with `guest_authorization_rejected` and
is a leak signal. The header value is not logged.

### When a RAM token is permitted

A short-lived access token may exist in guest RAM only when every item below
is true. Otherwise the launch fails with `provider_mode_unqualified` or
`ram_token_not_permitted`, and the mode stays disabled.

1. The signed binding mode is `qualified_ram_token`.
2. A mode-qualification record exists for that provider and mode with
   `qualified: true`, `helper_unsupported: true`, and `leak_scan: true`.
   The record's `qualification_digest` is enrolled on the node and on the
   gateway. Lane P produces it from a real account. A login is not enough.
3. `helper_unsupported` means the pinned CLI cannot be configured to send
   provider traffic through `127.0.0.1:1025`.
4. The material is an access token. It is not a refresh token and not an API key.
5. Its lifetime is at most 15 minutes and at most the remaining lease.
6. guestd writes it only to `/run/jeryu/provider-access` (tmpfs, mode 0600,
   uid 1000) from a vsock message that is not a terminal frame. It is not
   written to the workspace disk, the lease, the export, or a terminal frame.
7. Leak scanning of terminal frames and the export bundle is on for that
   session. A hit destroys the session and bumps `connection_generation`.

The node rejects `qualified_ram_token` unless the enrolled qualification
record is present. A binding by itself does not enable a provider profile.
If that record says the helper works (`helper_unsupported: false`), the
error is `helper_required` and the launch uses `gateway_helper` only after
the caller asks for that mode. The gateway does not switch modes.

## 3. Refresh, then lease

`connection_generation` is the credential identity. It changes when a
connection is created, replaced, or disconnected. A refresh does not change
it, and a live lease stays valid across token rotation. A refresh does not
need a new signed lease.

`secret_version` counts durable rotations of the stored secret. A new secret
starts at 0. It is vault-internal: not a lease field, not a capability
field, and not sent to the guest. The seal associated data includes it. A
blob sealed at `secret_version` N must not open when the row says N+1.

Refresh serializes on `connection_id`.

1. Take the lock. A waiter that cannot enter within 5 seconds gets
   `connection_busy` and no token.
2. Re-read state, `connection_generation`, `secret_version`, and the stored
   secret.
3. If state is `disconnected`, return `provider_not_connected` and stop.
4. Call the provider token endpoint from the vault, never from the guest.
   The vault sends the stored secret. It does not take a caller-supplied
   refresh token on this path.
5. Persist the rotated refresh token and `secret_version + 1` in one durable
   commit. `connection_generation` stays the same. An API key does not
   rotate and does not bump `secret_version`.
6. Only after that commit is durable, mint access material and capabilities
   at the same `connection_generation`. The gateway uses the current secret
   at that generation. It does not keep a secret cached when the capability
   was minted.
7. Release the lock.

If step 5 fails, mint nothing and leave the previous secret and
`secret_version` valid (`refresh_persist_failed`). If the provider rejects
the stored secret, leave the generation and `secret_version` unchanged and
do not mint. That rejection is not `connection_generation_stale`. A
presented refresh token that is not the stored one does not bump the
generation. Two refreshes cannot interleave a lease between the old secret
and the new commit.

In `qualified_ram_token` mode the node replaces the tmpfs access token
after step 6. The lease binding does not change. An old access token fails
the gateway compare (`ram_token_not_permitted`) and does not end the
session.

## 4. Disconnect and fencing

Disconnect sets `disconnected`, bumps `connection_generation`, and drops the
stored secret in the same commit. Replacing the credential does the same
bump and resets `secret_version` to 0. A running session bound to the old
generation needs a new signed lease. A refresh does not. In-flight gateway
calls re-read state and generation on every relay line. They do not trust a
capability for the rest of its TTL after a disconnect or a replacement.

Error precedence:

1. `provider_unknown`
2. `connection_owner_mismatch`
3. `provider_not_connected` when state is disconnected, even if the
   generation is also old
4. `connection_generation_stale` when state is connected and the generation
   differs
5. `provider_mode_disabled` or `provider_mode_unqualified`
6. `helper_required` when the helper can serve the profile
7. `ram_token_not_permitted`
8. `guest_authorization_rejected`
9. `capability_expired`
10. `capability_audience_mismatch`
11. `upstream_host_denied`
12. `connection_busy`
13. `refresh_persist_failed`
14. `lease_binding_mismatch`
15. `relay_idle_timeout`
16. `relay_stream_invalid`

## 5. K1 lease binding

Reviewed against lane R's uncommitted `managed-session-v2.1.md` and
`SessionLease::signing_bytes`. Accepted as published, except the mode enum
in section 2:

- `connection_bindings` is required, length 0 to 3, strictly ordered by
  provider, one binding per provider.
- Each binding is `provider`, `connection_id`, `connection_generation`,
  `mode`. No secret fields.
- Empty bindings are legal for `fixture` and `shell` only. Profiles
  `claude`, `codex`, and `grok` require a binding for that provider.
- The job digest domain is `jeryu.runner.managed-job.v2.1` and includes the
  binding list. Use the existing digest function once the mode enum matches
  this spec. Do not keep a second encoding.
- `signature` is 128 lowercase hex characters, a detached Ed25519 signature
  over `signing_bytes()`: the ASCII prefix `jeryu.runner.lease.v2.1`, one
  NUL, then the lease JSON without the `signature` field. Object keys are
  sorted recursively. Arrays keep their order. Numbers are integers.
  Floats are rejected.
- The node verifies that signature against the enrolled control-plane key
  before it reserves or boots a VM. mTLS remains required and is not
  sufficient. A request-supplied key cannot authorize a lease.
- v2.1 has one enrolled lease key. Rotation is a configuration restart.
  That is accepted for this version. It does not allow two keys to overlap.
- `validate_for_runner` does not itself verify the signature. A PR that
  boots on `validate_for_runner` alone is not K1.

`owner_id` on the lease context must equal the vault owner id, including
the `user/` or `service/` prefix.

## 6. K3 relay and capability

Guest path: loopback HTTP to `127.0.0.1:1025`, then vsock host port 1025.
The execution channel stays on vsock port 1024. No NIC. Frame bytes, the
flow window, and the gateway NDJSON hop are in `k3-relay-v1.md`. Lane R's
`GuestRelayRequest` is the metadata the node builds for the gateway. Accept
and Content-Type are the only guest headers, at most one of each, 256 ASCII
bytes. Authorization is not a guest metadata field in `gateway_helper` mode.

Reject paths that are not a single absolute path: no authority, userinfo,
fragment, backslash, control byte, empty or dot segment, or `//`.
Rejecting `?` and `%` is accepted until lane P enrolls a template that
needs a query. The extension is an optional `query` field, not a free URL.
Methods are GET and POST until an enrolled template names another method.

The node compares metadata to the admitted signed lease. The caller cannot
choose an account, a generation, or an upstream URL.

The node then calls the gateway at
`/internal/gateway/:session/:provider/*` over mTLS. The body starts with a
capability. The request and response bodies stream, with a 1 MiB buffer per
direction and a 60 second idle timeout. Bodies are not stored and not logged.
Redirects are not followed. A redirect or any host outside the allowlist is
`upstream_host_denied`.

Capability payload:

- `capability_id`, `connection_id`, `connection_generation`, `provider`, `mode`
- `owner_kind`, `owner_id`, `session_id`, `session_generation`
- `lease_id`, `lease_epoch`
- `audience` equal to `jeryu.gateway`
- `issued_at_unix_millis`, `expires_at_unix_millis`
- `signature`, 128 lowercase hex, domain prefix
  `jeryu.gateway.capability.v1` and one NUL, then the same canonical JSON
  rules as the lease, excluding `signature`

Lifetime is at most 60 seconds and must not pass the session lease expiry.
The gateway checks the signature, the audience, the owner, the mode rule in
section 2, and the live vault generation on every request.

In `qualified_ram_token` mode the gateway compares a guest Authorization
value to the current access token with a constant-time compare, then
forwards only on a match. A mismatch is `ram_token_not_permitted` and is
not logged.

### Upstream hosts

The gateway, not the guest, dials these hosts on TCP 443 only. No wildcards.
This list is not a qualification. Lane P must enroll path templates before
any real profile is enabled. Until then the enrolled path set is empty and
real provider profiles stay off.

| Provider | Hosts |
| --- | --- |
| claude | `api.anthropic.com` |
| codex | `api.openai.com` |
| grok | `api.x.ai`, `us.api.x.ai` |

Vault calls to provider token endpoints are separate and also fail closed
until lane P enrolls those hosts. The mock provider is loopback only and is
not on this list.

## 7. What this does not prove

It does not prove a vault, a gateway, a vsock relay, a node signature check,
or a real login. It does not prove three concurrent VMs share one human
login. Lane R's K2 subscribe schema and K4 bundle schema were read with K1.
K2's stream shape is consistent with §21.3 and is not wired into runnerd in
the tree that was read. K4 is not a connection contract. Neither schema is
accepted as a running service.
