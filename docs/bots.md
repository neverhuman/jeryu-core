# Bots

Bot enrollment keys are one-time secrets. Exchanging one returns a bot session
with a refresh token, and every refresh rotation returns a new refresh token.
Core stores refresh-token hashes, never the token material, so clients must keep
the newest refresh token they receive.

## Refresh Retries

`POST /api/v1/bot/token/refresh` clients that opt in to idempotency should send
the same `Idempotency-Key` when retrying a request whose response may have been
lost. The key is at least 32 visible characters from a CSPRNG, and it is bound
to the presented refresh token as well as the request body. Core records the
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
refresh token without the matching idempotency key, with a different request
body, or after the grace window still revokes the family and bumps the bot's
credential generation. The shipped bot proxy does not send an idempotency key,
so it stays on the ordinary single-use refresh path. A server with no vault
key refuses the idempotent path rather than storing the token.
