# mock-provider-v1

Lane A spec. Lane C implements it as a test crate in `jeryu-deploy`.
Lane A reviews that crate. It is not linked into `jeryu-api`, `runnerd`,
or `jeryu-session-node`. A policy test must fail the build if it is.

The process binds `127.0.0.1` on an ephemeral port only. It refuses
`0.0.0.0`. It has no HTTP client and no DNS lookup. The source of the
crate must not contain `api.anthropic.com`, `api.openai.com`, `api.x.ai`,
or `us.api.x.ai`. Those strings live in `connection-v1.md`, not here.
`outbound_dial_attempts` stays 0.

Server flags, not client fields, set `access_ttl_ms`, `refresh_ttl_ms`,
`rotate_refresh` (default true), and `fail_persist_once`. Test hooks are
on because the binary is test-only.

## States

`pending_device`, `connected`, `refreshing`, `disconnected`.
One mutex per `connection_id` covers refresh. The event log is the proof
of order. `GET /events` returns `[{seq, kind}]` with kinds
`refresh_persisted`, `access_lease_issued`, and `generation_bumped`.
`generation_bumped` is connect, credential replacement, and disconnect.
A refresh does not emit it. A lease event must not sit between the start
of a refresh and `refresh_persisted`.

## Endpoints

`POST /oauth/device` with `provider`, `owner_kind`, `owner_id`, `mode`,
and `provider_account`. Response: `device_code`, `user_code`, `interval`,
`expires_in`, and `verification_uri` of `http://127.0.0.1/mock-device`.
State becomes `pending_device`. Unknown provider, including `jekko`, is
`provider_unknown`.

`POST /oauth/device/approve` with `user_code` marks the device approved.
This route exists only on the mock.

`POST /oauth/token` accepts `grant_type` `urn:ietf:params:oauth:grant-type:device_code`
or `refresh_token`.

- Device grant before approval returns `authorization_pending`.
- Expired device code returns `expired_token`.
- Approved device grant persists the refresh token at generation 1, then
  returns `access_token`, `refresh_token`, and `expires_in`.
- Refresh takes the connection lock, checks state, and checks that the
  presented refresh token is the stored one.
- Disconnected returns `provider_not_connected` and does not mint.
- A token that is not the stored refresh token returns `invalid_grant`.
  `connection_generation` and `secret_version` stay unchanged.
- The new refresh token is written and fsynced, `secret_version` increments,
  `connection_generation` stays the same, and only then is an access token
  returned.
- `fail_persist_once` fails the write, mints nothing, and leaves the old
  refresh token and `secret_version` valid.

`POST /sessions` with `connection_id` and `connection_generation` mints an
access lease for a new `session_id` without another refresh when the
current access TTL is still valid. Three concurrent calls on one connection
must all succeed. The same generation still succeeds after a refresh. A
stale generation increments `stale_generation_refusals` and returns
`connection_generation_stale`.

`POST /connections/{id}/disconnect` bumps the generation, sets
`disconnected`, and deletes the refresh token in one persist. Later token
and session calls return `provider_not_connected`.

`POST /v1/messages`, `POST /v1/chat/completions`, and `POST /v1/responses`
require `Authorization: Bearer` equal to a live access token for that
session and generation. They return 200 and `{"injected": true}` on
success. A missing header, a refresh token used as the bearer, an expired
token, or a stale generation returns 401. The mock does not add a
credential itself. The test gateway sets Authorization. That is the
injection proof.

`GET /counters` returns the counters below. Tokens do not appear in this
body or in logs.

## Counters the CI-A test must assert

| Counter | Required result |
| --- | --- |
| `connections_issued` | 1 after one device login |
| `concurrent_sessions_peak` | at least 3 |
| `refreshes_persisted` | increments before `access_leases_issued` for that refresh |
| `refresh_before_lease_ok` | increments once per successful refresh |
| `stale_generation_refusals` | increments when generation N is used after disconnect or replacement moved the identity to N+1 |
| `chat_authorized` | increments only when the injected access token matches |
| `chat_rejected` | increments for the refresh token, a missing header, and a stale token |
| `outbound_dial_attempts` | 0 |

One connection serves the three sessions. A refresh leaves that generation
valid. Disconnect fences it. The test scans logs with `ops/ci/leak-oracle.sh`
and does not print the tokens.

This crate does not prove a real provider, a vsock, or KVM.
