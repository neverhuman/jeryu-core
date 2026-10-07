# connection-v1

Lane A spec for provider connections, the K1 lease binding, and the K3 relay.
Location: `jeryu-core/contracts/connection-v1/` on branch `lane-a/contracts`.

This directory is not `contracts/generated/`. Do not treat these files as
TypeScript emitted from Rust. Lane R's serde types remain the runner wire
authority. Where this spec and that wire disagree, the disagreement is a
review finding until both sides match.

| File | What it is |
| --- | --- |
| `connection-v1.md` | Normative rules. A message is valid only if it satisfies these rules and `connection-v1.schema.json`. |
| `connection-v1.schema.json` | Closed JSON shapes. No secret fields. |
| `k3-relay-v1.md` | Relay stream frames and the gateway hop. |
| `k3-relay-v1.schema.json` | Closed frame shapes for that stream. |
| `mock-provider-v1.md` | State machine Claude implements as a test crate in `jeryu-deploy`. |
| `mock-agent-v1.md` | One binary, `argv[0]` selects mock-claude, mock-codex, or mock-grok. |
| `leak-oracle-v1.md` | Canary rules for CI-A (no KVM) and CI-B (KVM). |

The matching helpers are `ops/ci/launch-inventory.sh` and `ops/ci/leak-oracle.sh`.
Inventory is report-only until migration milestone M6.

This spec does not implement a vault, a gateway, a guest relay, or a login.
It does not prove KVM isolation, refresh against a real provider, or that host
launches are gone.
