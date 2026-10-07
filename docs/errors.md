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

Enrolling or rotating a Grokbot or Musebot rejected the slug, display name,
reach, key environment, or account. Use a login-shaped slug, keep the display
name within 80 characters, and choose general reach, at most 100 repositories,
or one issue, pull, or branch.

## Bot credential

The enrollment key or refresh token is not current for an active Grokbot or
Musebot. Present the enrollment key or the latest refresh token. The enrollment
key is shown once and stays valid until it is rotated or revoked, or the
account's password changes or it is disabled or locked; treat it as the bot
host's long-lived secret. Do not send either as a bearer. A reused refresh
token revokes the family; exchange the enrollment key again to recover.

## Bot conflict

The account already has that slug, or an idempotency key was replayed with a
different body. Choose another slug, or resend the original body with the same
idempotency key.

## Bot reach

The call sits outside the owner's non-admin grant. The repository is not
granted, the task is not the granted one, or the effect exceeds the owner's
rights. Narrow the call. Do not request forge admin, release, pin, or user
administration.

## Bot missing

No Grokbot or Musebot credential exists for that id, or it has been revoked.
Enroll again, or list the account roster. A revoked credential is not found
for rotation.

## Bot storage

The forge could not read randomness or build the Argon2id hash for a new
enrollment secret. Retry the enroll or rotate once. Do not keep the secret if
the hash fails.
