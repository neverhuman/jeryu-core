# 0001. Revoke every session and API credential on password recovery

Status: Accepted
Date: 2026-10-28
Supersedes: none
Superseded-by: none

## Context

Core gains self-service password recovery: `issue_password_recovery` mints a
single-use secret that the edge mails to the account, and the holder of that
secret sets a new password with it. It is the first password path that does
not need the current password or an administrator.

Every other password path revokes the account's credentials.
`change_account_password`, `reset_account_password` and
`force_password_change` bump `auth_epoch`, end browser sessions, delete
personal access tokens, and call `invalidate_account_bots`. That revokes the
keys, refresh tokens and agent tokens of the account's own bots. The
invariant is written down in `db/AGENTS.md` and `db/constraints.md`.

The first design of recovery kept API credentials. A person who proves they
own the mailbox and picks a new password would keep their automation running,
and only browser sessions would end. That makes recovery the one password
path that does not cut off a leaked credential. Yet recovery is what a person
reaches for when they think the account is compromised. The project owner
decided against keeping credentials.

## Decision

A password recovery revokes every session and API credential of that account,
exactly like `change_account_password`. `recover_password`:

- bumps `auth_epoch`, and clears a forced password change;
- ends every browser session of the account;
- deletes every personal access token of the account;
- calls `invalidate_account_bots` for the account, which revokes its own
  bots' enrollment keys and refresh tokens and raises their
  `credential_generation`, so their agent tokens stop working.

It reports what it ended in `PasswordRecoveryReceipt` (`sessions_ended`,
`personal_access_tokens_revoked`). It records the same counts in its
`forge_audit_log` row.

Nothing outside the account changes:

- Other accounts keep their sessions, tokens and bots.
- Repository grants stay. They are the account's permissions, not
  credentials, and a password change keeps them too.
- A team bot belongs to its organization. A token for it, even one this
  account issued as a steward, keeps working, as it does after a steward's
  password change (jeryu-deploy ADR 0008). Disabling the account, or removing
  it from the steward team, is what revokes the tokens it issued.

There is no keep-tokens variant of recovery.

## Consequences

- A leaked personal access token, bot key or agent token stops working when
  its owner recovers the account, without a separate revoke step.
- Recovering costs the account its automation. After a recovery the person
  creates new personal access tokens and rotates each bot's key
  (`rotate_bot_key`) to bring the bots back. `docs/errors.md` says so.
- Every password path now has one rule, so `db/AGENTS.md` and
  `db/constraints.md` no longer carry an exception.
- The edge that wires recovery into a forgot-password page must tell the
  person, before they confirm, that their tokens and bots will stop.
