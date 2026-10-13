# Bots

Bot enrollment keys are one-time secrets. Exchanging one returns a bot session
with a refresh token, and every refresh rotation returns a new refresh token.
Core stores refresh-token hashes, never the token material, so clients must keep
the newest refresh token they receive.

## Refresh Retries

`POST /api/v1/bot/token/refresh` clients that opt in to idempotency should send
the same `Idempotency-Key` when retrying a request whose response may have been
lost. Core records the refresh rotation and the serialized success response in
one write. A retry that presents the just-spent refresh token with the same
idempotency key and the same request body within the five-minute rotation grace
receives the same successor refresh token instead of revoking the refresh
family.

The grace path is only for replaying that completed operation. Reusing a spent
refresh token without the matching idempotency key, with a different request
body, or after the grace window still revokes the family and bumps the bot's
credential generation. The shipped bot proxy does not send an idempotency key,
so it stays on the ordinary single-use refresh path.
