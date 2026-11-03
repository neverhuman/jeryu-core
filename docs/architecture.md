# Architecture

Jeryu is a local GitHub-compatible forge implemented as Rust workspace crates and local operational scripts. Compatibility means matching observable API and workflow behavior where that is useful for users and agents; it does not mean copying GitHub source, bundling GitHub assets, or requiring a hosted GitHub dependency.

Core boundaries:
- `crates/jeryu-core` and `crates/jeryu-api` own forge domain and API behavior.
- `crates/jeryu-gitd` owns repository storage and Git protocol behavior.
- `crates/jeryu-ci-*`, `crates/jeryu-runner-*`, and `crates/jeryu-runnerd` own CI IR, scheduling, and execution.
- `crates/jeryu-cache*` owns cache/CAS policy and poisoning resistance.
- `crates/jeryu-proof` and `crates/jeryu-agentbridge` own proof routing and bounded agent mutation.
- `crates/jeryu-codegraph` owns hosted code-oracle indexing and impact packs
  for resolved repo refs; see `docs/codegraph-oracle.md`.

The production `jeryu-gitd` TCP edge streams smart-HTTP upload-pack and
receive-pack bodies concurrently between the authenticated client socket and
stock Git child pipes. Request and response packs are never accumulated in a
`Vec`; socket and pipe backpressure bound memory, while receive-pack buffers
only a capped command prelude for protected-ref policy. The same production edge
streams authenticated Git LFS object downloads directly from an opened regular
object file to the client socket with an exact `Content-Length`; it never
materializes the object in a response `Vec`. The public
`SmartHttpServer::route(HttpRequest)` API is fully materialized: the request
body and the whole pack response are held in memory. The unified `jeryu serve`
mounts `/git` through it today (jeryu-deploy `git_transport.rs`, with its own
bounded body reads), so a clone's pack is buffered once per concurrent request
there.

Buffered smart-HTTP pack RPCs (`route()`, the `jeryu serve` path) pass
`jeryu_gitd::pack_rpc`: at most `JERYU_GITD_MAX_PACK_RPCS` run at once
(default: available parallelism, 2..=64); a request waits up to
`JERYU_GITD_PACK_RPC_WAIT_SECS` (default 30, clamped 1..=300) for a slot and is
otherwise answered `503` with `Retry-After`. A slot covers only the `git`
child's work: the body is already in memory and the response is returned as
bytes. The streaming paths (`serve()`, `prepare_pack_rpc`) pump client sockets,
so they are recorded but never take a slot. SSH sessions (one process each) and
ref advertisement (`info/refs`) are neither bounded nor recorded. Each recorded
RPC writes one `{"event":"gitd.pack_rpc",...}` line to stderr with its service,
repository, bytes in and out, wait, duration, concurrency and outcome.

Every receive-pack runs with `receive.fsckObjects=true`, so Git rejects a
malformed object a push sends while unpacking it; the pre-receive guard no
longer runs a whole-repository `fsck --strict` on each push. That narrows what
is checked to each push's own objects: objects imported by `jeryu_gitd::mirror`
(clone or fetch from a remote) are not checked by either path.

The shared workcell control plane is part of the runner/CI stack, not a separate subsystem. `jeryu-runnerd` owns warm-pool claims, epoch-fenced release/heartbeat handling, startup rebase enforcement, and quarantine-first tar validation on top of the existing runner fabric.

The R5 proof lane lives in `crates/jeryu-api` and closes the loop from claim to reviewed pull request: rebase, jailed edit, namespaced branch export, PR creation, and CI evidence verification. The export request carries the changed-file list so the pull request preserves branch ownership and reviewer-visible edit scope.

JMCP/control-plane intelligence is an API/read-model boundary over local truth:
the local forge store, runner fabric, workcells, agent runs, codegraph, and
tool-build clusters are authoritative, while GitHub mirror data is optional
read-only evidence that must degrade as `missing`, `stale`, `queued`, `failed`,
or `unknown` rather than becoming an implicit green signal.

Operational truth is local-first. The canonical validation surfaces are `Justfile`, `ops/ci/*.sh`, `ops/ci/gates/*.sh`, and `agent/test-map.json`.
