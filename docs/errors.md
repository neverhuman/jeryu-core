# Error Repair Surface

Jeryu domain errors expose an `AgentRepairHint` with five required fields:
`purpose`, `reason`, `common_fixes`, `docs_url`, and `repair_hint`.
Agents should route failures from this typed surface instead of scraping display
strings.

## Not Found

The requested repository, pull request, queue entry, receipt, or other domain
entity was not present in the current read model. Verify the typed id, refresh
the read model, and rerun the owning crate test.

## Invalid Input

The request failed boundary validation before the domain operation ran. Add or
rerun the boundary test for the rejected input shape before changing policy.

## Policy Denied

A branch, proof, queue, cache, runner, or release policy intentionally blocked
the operation. Preserve the guard and supply the required proof, approval, trust
receipt, or signed witness.

## Conflict

The operation would violate merge or state consistency. Refresh base state,
recompute the witness, and retry through the queue path.

## Missing Receipt

The operation needs durable evidence before mutation. Produce the required
release, cache, scheduler, webhook, or audit receipt and rerun the mapped proof
lane.

## Missing Proof Witness

The merge path needs proof for the exact head commit and owned paths. Run the
owner/test-map proof lane and regenerate the witness before retrying merge.

## GitHub CLI Auth Steering

Jeryu does not repair a local-host GitHub CLI problem by running `gh auth login`,
`gh auth refresh`, scraping `hosts.yml`, or hunting credential stores. Configure
the host entry with `jeryu gh-setup --host <local-jeryu-url> --token-file
~/.jeryu/secrets/merge-token`, then use `/.jeryu/capabilities`, the Jeryu REST
routes, or the `jeryu.*` MCP tools for the original PR, CI, issue, or repository
task.

If `gh` reports a stale or invalid token for an existing local Jeryu host entry,
rerun `jeryu gh-setup --host <same-local-host> --token-file
~/.jeryu/secrets/merge-token`. GitHub.com auth and local Jeryu host auth are
separate; do not run `gh auth login` for Jeryu hosts. The vault bootstrap file
at `~/.jeryu/vault/bootstrap.json` contains vault bootstrap material and is not
the `gh` host repair path.

Native agent credentials are separate from the GitHub-compatible host entry.
Use `jeryu agent auth doctor <tool>` and `jeryu agent auth import --from-host
<tool>` for portable Codex, Claude, or Jekko CLI credentials.

## Workcell Control Plane

Workcell claims, heartbeats, startup rebases, tar quarantine checks, and
branch-budget enforcement are repairable failures, not silent fallbacks. The
runnerd helpers return a typed `WorkcellError` with the same five-field repair
shape used elsewhere in the product:

- `purpose`
- `reason`
- `common_fixes`
- `docs_url`
- `repair_hint`

Use the docs-linked sections in `docs/testing.md#workcells` and
`docs/boundaries.md#workcells` to repair claim, epoch, path, or merge/delete
denials.

## Agent Run Control

High-level `/api/v1/agent-runs` failures use the same typed repair shape. Common
codes include `agent_run_workcell_state_denied` for non-held/non-repairing
workcells, `workcell_epoch_fenced` for stale failed-CI repair requests,
`agent_run_path_denied` for out-of-slice repo roots or programs,
`agent_run_control_unsupported` for controls sent to pipe-mode runs, and
`agent_run_finished` for controls sent after the driver has completed.

Use `docs/workcell.md#agent-run-control-surface` and rerun
`cargo test -p jeryu-api --features web --jobs 40 agent_runs`.

## Codegraph Oracle

Codegraph query failures are typed repairable API errors. Missing repositories
return `not_found`; malformed bodies return `invalid_input`; unresolved refs
return `invalid_ref`; checkout or index failures return codegraph-specific
repair messages. Use `docs/codegraph-oracle.md` for the route contract and
`docs/testing.md#codegraph-oracle` for rerun commands.

## Bot enrollment

Enrolling or rotating a bot rejected the slug, display name, kind, reach, key
environment, or account. Use a login-shaped slug, keep the display name within
80 characters, and choose general reach, 1 to 20 distinct owners, at most 100
repositories, or one issue, pull, or branch. A kind matches
`^[a-z][a-z0-9-]{0,31}$`; an invalid one is `invalid_bot_kind`. An owners
reach that is empty, names more than 20 distinct owners, or names an owner
that is not an account or organization on this forge is
`invalid_reach_owners`.

## Bot credential

The enrollment key or refresh token is not current for an active Grokbot or
Musebot. Present the enrollment key or the latest refresh token. The enrollment
key is shown once and stays valid until it is rotated or revoked, or the
account's password changes or it is disabled or locked; treat it as the bot
host's long-lived secret. Do not send either as a bearer. A reused refresh
token revokes the family; exchange the enrollment key again to recover.

A password recovery from a mailed link ends the key too, like a password
change: it revokes the account's bot keys, refresh tokens and agent tokens.
Rotate the key to bring the bot back.

## Bot conflict

The account already has that slug, or an idempotency key was replayed with a
different body. Choose another slug, or resend the original body with the same
idempotency key.

## Bot reach

The call sits outside the owner's non-admin grant. The repository is not
granted, the task is not the granted one, or the effect exceeds the owner's
rights. An owners reach covers only repositories of the listed owners on which
the bot's owner holds an explicit grant; a public read is not enough. Narrow the call. Do not request forge admin, release, pin, or user
administration.

## Bot missing

No Grokbot or Musebot credential exists for that id, or it has been revoked.
Enroll again, or list the account roster. A revoked credential is not found
for rotation.

## Bot storage

The forge could not read randomness or build the Argon2id hash for a new
enrollment secret. Retry the enroll or rotate once. Do not keep the secret if
the hash fails.

## Store custody

One forge process writes a database, through one store. `store_locked`: another
process, or another open in this process, has it; run one forge per data
directory, and share a store by cloning its ForgeCore. `store_aliased`: the
database file has a second hard link, or the path is a link to nothing; open
it by its one path and remove the extra link. `store_replaced`: the path no
longer names the file this store opened; do not move or replace forge.sqlite
while the forge runs, and restart it. `store_journal`: the database is in WAL
mode, and the store keeps a rollback journal; the forge never converts it on
open. With the forge stopped, run `PRAGMA journal_mode = DELETE;` on it once
(for example with the `sqlite3` shell), then start the forge.

## Waitlist

The public waitlist cannot store another new address. A repeat of an address
already stored is not this error. Keep the existing address. Do not retry a
new one in a loop. An operator reviews the list.

## Password recovery

`password recovery could not be completed` is the one answer for every refused
recovery, so it does not tell anyone whether a login exists or is active. The
link may be unknown, already used, replaced by a newer link, older than an
hour, or used with a wrong secret five times. The account may also be disabled
or locked, or its password may have changed since the link was sent. Ask for a
new link. A password shorter than 12 bytes is refused first and does not use
the link up.

A completed recovery works like a password change: it ends every browser
session of the account, deletes its personal access tokens, and revokes the
keys, refresh tokens and agent tokens of its own bots. Sign in again, create
new tokens, and rotate each bot's key. Repository grants stay. Tokens of a team
bot belong to its organization and keep working.
