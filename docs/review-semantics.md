# Core review semantics and integration boundary

`ForgeCore::create_review` records explicit approvals, changes requests and
comments. Comments preserve the actor's current explicit verdict. Authors cannot
approve their own PR, including through direct Core callers; inherited self
approvals cannot satisfy required approval counts or CODEOWNERS or erase an
earlier rejection.

`ForgeCore::dismiss_review` requires a target UUID, full lowercase SHA-1 current
head and nonempty reason. Only the target's own reviewer may dismiss the current
explicit verdict.
The operation appends a `DISMISSED` event with `dismissed_review_id` and the reason
in `body`. It never changes the target row. Superseded, already-dismissed,
wrong-head and other-actor targets are refused. Generic `event=DISMISSED` review
creation is unsupported. Later explicit decisions can establish a new verdict;
dismissal never recovers an older verdict. Historical target-less dismissals
suppress prior approvals without erasing rejections or inferring targets.

The shared `effective_reviews_for_pull_request` helper must supply both
qualification and consumer posture. The head-only reducer remains available for
audit and target selection. SQLite migration 0016 preserves targets and append
order through reopen and unrelated full-state writes. See `db/constraints.md`
for installation custody and incompatible older writers.

Actor parameters remain raw canonical login strings. The caller must authenticate
their holder and enforce repository access. Existing implicit profile creation
is now inside the validated review transaction and rolls back with it; a profile
does not create an account or authenticate a credential. Generic review creation
still accepts an optional expected head. This change does not establish review
nonces, actor capabilities, credential-revocation serialization, multiple-writer
exclusion, merge recovery or installed authority qualification.

## Required Deploy and Web integration

Before consuming this Core cut, Deploy must map the new `ForgeError::Forbidden`
to 403 in `crates/jeryu-api/src/web/pulls.rs`, `src/github/support.rs`, and
`src/web/workcells_support.rs`. These are exhaustive matches. Its PR posture and
history must use `effective_reviews_for_pull_request`, and the `PullRequestReview`
constructor must include `dismissed_review_id`. The existing COMMENTED history
assertion in `src/web/tests.rs` must expect `effective=false` while preserving
the row and thread. Authentication must come from the actual request holder,
never a submitted actor login.

The new source contract `DismissPullReviewRequest` supplies `expected_head_sha`
and `reason`; the target UUID is a route parameter. Add authenticated native
review-history GET and targeted self-dismissal POST routes using this Core
operation. Required route regressions cover 401, 403, malformed bodies, stale
heads, no administrator override, unchanged history on refusal and matching
posture/history after success. Durable history sequence and complete authority
bindings are still required by the broader program.

Generate contracts from Rust with
`cargo run --locked -p jeryu-readmodel --bin export_contracts` after CI allocation;
do not hand-edit generated output. Include the generated cut and Web typecheck
with the eventual consumer pin. Source changes remain unqualified until these
consumer changes and their tests pass.

## Verification commands

Run in the allocated CI window with `CARGO_BUILD_JOBS=2`:

```sh
cargo test --locked -p jeryu-core --test review_semantics
cargo test --locked -p jeryu-core --lib migration_0016_preserves_unbound_dismissals
cargo test --locked -p jeryu-core
cargo test --locked -p jeryu-readmodel
cargo clippy --locked --workspace --all-targets -- -D warnings
jankurai migrate . --analyze --out target/jankurai/migration-report.json
```

The full governed fast, check, score and security lanes remain required before
acceptance. These commands describe the required checks; they are not receipts.

## Audited merge decisions

Core exposes `prepare_merge_override` and `finalize_merge_with_override` as a
source integration primitive. Existing rules deserialize with
`allow_merge_override=false` and empty status-context/status-creator allowlists.
An active repository administrator other than the PR author can prepare a
10-minute permit only when the branch explicitly opts in,
and every normal blocker is a failed commit status named in that allowlist.
Repository-admin authority comes from the one authorization model
(`repo_access_for`), and a team bot's acting login is refused outright: an
audited decision is a human administrator's.
Separation of duties binds the decision: the required approving reviews must be
satisfied without the deciding administrator's own approval, and the failing
status row used as evidence cannot be one it created.
The latest failing status must come from an explicitly trusted authenticated CI
creator; its full row is bound in the permit and recorded in the receipt. An
active check-run rerun blocks the decision. A branch with `enforce_admins` on
("Include administrators") has no override at all: there its rules bind every
actor, administrators included.
Pending/missing checks, independent approvals, standing review holds, CODEOWNERS,
proof, signed commits, history, draft state and exact-head checks remain binding.
No installed branch protection is changed by this source change.

The permit binds head, base, actor, reason, full protection and evaluation.
Preparation returns a `MergeOverrideTarget`, not `MergeReadiness::Ready`: the
ordinary gate has not passed, and the Git phase must finalize through
`finalize_merge_with_override`.
Finalization rechecks all of them, the exact status evidence and current grants. SQLite storage is required;
merge state and the completed audit entry commit in one transaction. Every
refusal records a `failed` entry — preparation refusals carry `stage=prepare` —
and persistence failure restores in-memory state. A failure to append the
receipt never replaces the refusal reason the edge needs. The
`asserted_passport_hash` request requires a `passport:<64 lowercase hex>` shape.
The `caller_asserted_passport_hash` audit field (recorded with
`passport_hash_verified: false`) records an edge assertion, not a Core-verified
passport: an integrating authenticated edge must independently validate that
assertion and Git conflict/ref state, and recover a Git advance if finalization
fails. This Core PR adds no HTTP bypass route or deployed override capability.

Run `cargo test --locked --offline -p jeryu-core merge_override` for the focused
receipt, expiry, rollback, opt-in, pending-check and review-gate regressions.
The full Core suite remains required before this cut is consumed.
