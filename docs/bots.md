# Bots

Bot enrollment keys are one-time secrets. Exchanging one returns a bot session
with a refresh token, and every refresh rotation returns a new refresh token.
Core stores refresh-token hashes, never the token material, so clients must keep
the newest refresh token they receive.

## Refresh Retries

The engine method is `rotate_bot_refresh_token_idempotent`. No edge route in
this repository reads an `Idempotency-Key` header yet, so a client cannot call
this path over HTTP until that route exists. Callers that do opt in send the
same idempotency key when retrying a request whose response may have been lost.
Core accepts 32 to 128 visible ASCII characters. It cannot tell whether the
caller drew them from a CSPRNG; a predictable key lets anyone who later sees
the spent refresh token replay the successor during the grace window. The key
is bound to the presented refresh token as well as the request body. Core records the
rotation and a vault-sealed copy of the successor token in one write. The
sqlite row holds ciphertext, not the token. A retry that presents the
just-spent refresh token with the same key and body, within the five-minute
rotation grace, receives that successor again instead of revoking the family.
The replay runs only when the bot is still active, the key is still live, the
sealed payload names this token's bot, key, and generation, and the successor
itself is still unused. Each replay writes a `bot.refresh.replay` audit row.

`bot.token.refresh` is reserved. The public idempotency API rejects that
operation name. On open, Core drops any `bot.token.refresh` row whose
`result_json` is not a vault envelope, including rows planted before this
seal existed.

The grace path is only for replaying that completed operation. Reusing a spent
refresh token without the matching idempotency key, or after the grace window,
still revokes the family and bumps the bot's credential generation. A retry
that presents the matching key with a different request body returns
`idempotency_conflict` and does not revoke, so the client can send the original
body. If the successor itself was already used, the replay is refused and the
family is not revoked again. The shipped bot proxy does not send an idempotency key,
so it stays on the ordinary single-use refresh path. A server with no vault
key refuses the idempotent path rather than storing the token.

## Team Bots

A bot is owned by a person or by an organization (records 0008 and 0009 in
jeryu-deploy's `docs/adr/`). A person's bot is unchanged: it acts as its
owner, under the owner's non-admin grants cut down by its reach.

An organization's bot is a team bot (`engine/team_bots.rs`):

- **Its own grants.** `grant_bot_repository` gives it `read` or `write` on one
  repository, never `admin`; only that repository's administrators, or a forge
  administrator, may. Grants are keyed by bot id and repository id, so a
  repository move keeps them and deleting the repository drops them. Its
  reach narrows those grants exactly as for a person's bot.
- **Its own name.** It acts as `<organization>.<slug>[bot]`
  (`team_bot_login`). Account logins cannot contain `.` or `[`, so no account
  can carry that name. `repo_access_for` resolves it to the bot's own grant,
  so every `user_can_*` check sees the bot's rights and never `admin`.
  `bot_acting_account` gives the edge the account summary to run a request as.
- **Stewards.** Members of the bot's steward team, and forge administrators,
  rotate its key, suspend or revoke it, read its activity, and issue or revoke
  its tokens. The organization's owners enroll team bots, and steward them
  only from the team.
- **Agent tokens only.** Exchanging a team bot's enrollment key always fails.
  Each agent token records `issued_by`, and authenticates only while that
  login may still steward the bot. Leaving the steward team, or a disabled or
  locked account, revokes the tokens that person issued; a password change
  does not. `revoke_issued_team_bot_tokens` revokes all of one person's at once.
