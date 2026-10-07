# k3-relay-v1

Lane A. Normative frame rules for the credential relay. Shapes are in
`k3-relay-v1.schema.json`. Policy, modes, and error precedence stay in
`connection-v1.md`. A frame is valid only if it satisfies both.

This does not implement guestd, the node relay, or the gateway.

## Ports and who fills identity

The guest execution channel remains vsock port 1024. The relay is a second
socket, vsock host port 1025, one connection per VM. guestd binds
`127.0.0.1:1025` and is the only guest process that dials vsock. The agent
uses loopback HTTP only.

The guest does not send `session_id`, generation, lease id, or owner. The
node fills those from the admitted signed lease when it builds
`GuestRelayRequest` for the gateway. A guest frame that contains those
fields is `relay_stream_invalid`. At most four relay requests are in flight
per VM. A fifth `open` is `connection_busy`.

## Encoding

Each vsock frame is a 4-byte big-endian length and then one JSON object,
same layout as the execution channel. The JSON is at most 256 KiB.
`bytes_b64` is standard base64 with padding. Decoded length is 1 to 32768.
Sequence numbers start at 1 and are contiguous per direction. A gap, a
second `open` for the same `request_id`, or a frame after `request-end` or
`response-end` is `relay_stream_invalid`. Unknown fields are rejected.

60 seconds with no frame on that request is `relay_idle_timeout`. The node
then stops the gateway call. Body bytes are not logged. Counts, status, and
the error code may be logged.

## Guest to node

1. `open` carries `request_id`, `provider`, `GET` or `POST`, the path, and
   at most one `accept` and one `content-type`.
2. Zero or more `request-body` frames, `seq` contiguous.
3. `request-end` with `seq_end` equal to the last body seq, or 0 when there
   is no body.

`cancel` may follow `open`. The node stops the gateway stream and sends no
`response-end`. In `gateway_helper` mode an `authorization` field is
`guest_authorization_rejected` and is not forwarded. In
`qualified_ram_token` mode that field may hold the access token. The node
forwards it only inside the mTLS body, never in a URL, a log, a terminal
frame, or the workspace.

The path rules in `connection-v1.md` section 6 apply to `open.path`.
guestd strips `Bearer jeryu-placeholder` before `open`. Any other
Authorization in helper mode never becomes a frame.

## Node to guest

1. `head` carries the HTTP status (100 through 599) and at most one
   `content-type`. No other response header is forwarded. `set-cookie` and
   `authorization` are dropped.
2. Zero or more `response-body` frames.
3. `response-end` with `seq_end` of the last response body, or 0.

An `error` frame ends the request. The node sends no body after it. If the
gateway has already started a response and then reports
`provider_not_connected` or `connection_generation_stale`, the node drops
the remainder and sends `error` only.

## Window

Each direction may have at most 1 MiB of body bytes that the peer has not
acked. `ack` names `through_seq`. The sender stops at the window. This is
backpressure, not a dropped chunk. The execution channel's terminal ring is
not the relay window.

## Gateway hop

The node opens one mTLS `POST /internal/gateway/{session_id}/{provider}`
with `content-type: application/x-ndjson`. The first line is a
`gateway-open` object: the capability from `connection-v1.md` section 6
plus the node-built relay metadata (`request_id`, method, path, headers,
provider). Following lines are `request-body`, then `request-end`. The
response is NDJSON: `head`, `response-body` lines, `response-end`, or one
`error` line. Each line is at most 256 KiB. The URL contains no token.
The gateway applies `connection-v1.md` section 6 on every line and does not
follow redirects. `expires_at` is checked only on `gateway-open`. Later
lines of that `request_id` stay valid after `expires_at` while the idle
timeout and the session lease still hold. A new `gateway-open` for the same
`request_id` is `relay_stream_invalid`. A new request uses a new capability.

The node checks the admitted lease is still the one it booted before it
forwards `open` and before it forwards each `request-body`. It does not
cache a gateway success past that check.

## Order the CI-A fake must show

- Helper mode: placeholder stripped, gateway sees the vault credential,
  guest frames have no authorization field.
- Four `open`s on one VM succeed; the fifth in flight returns
  `connection_busy`.
- A generation bump between `request-body` frames returns
  `connection_generation_stale` or `provider_not_connected` and no further
  response body.
- A 32769-byte decoded chunk is `relay_stream_invalid`.
- `gateway-open` after `expires_at` is `capability_expired` and opens nothing.
  A `response-body` line after `expires_at`, on a request opened before
  `expires_at`, is forwarded when the generation is unchanged.
- A second `gateway-open` for the same `request_id` is `relay_stream_invalid`.
- `outbound` from the fake guest to `api.anthropic.com`, `api.openai.com`,
  `api.x.ai`, or `us.api.x.ai` stays impossible.

Lane R implements the guest and node side of these frames. Lane C implements
the NDJSON gateway. Neither side is enabled for a real provider until a
path template is enrolled.
