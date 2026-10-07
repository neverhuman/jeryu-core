# leak-oracle-v1

A canary is one line of at least 24 bytes, prefixed with `jeryu-canary-`
when `secret-probe` is the guest searcher. CI generates it for the run.
It is not a provider token. Passing the oracle does not prove a real token
is absent. It proves this canary did not show up in the places below.

The helper is `ops/ci/leak-oracle.sh`. It reads the canary from a mode-0600
file and searches with `grep -f`. It must not receive the canary as an
argument, print it, or write it into the report. Exit 0 is absent. Exit 1
is a hit or a bad probe. Exit 2 is a usage error.

Scanned surfaces, every run:

- Guest-visible files the harness is allowed to read
- Terminal frames and replay rings
- The export bundle
- Runner, gateway, and test logs

The canary file itself is not a hit.

## CI-A, no KVM

The fake guest directory is a normal directory, so the helper scans it.
The test plants the canary only in the vault stand-in. `secret-probe` runs
in the fake guest. The helper then scans the fake guest tree, the frame
log, the export bundle, and the mock-provider log, and it checks
`--require-probe` on the frame log. Required probe line:
`LEAK_ORACLE_PROBE=absent`. Zero lines of `LEAK_ORACLE_PROBE=present`.

The connect-once test (one connection, three sessions, refresh, disconnect)
uses the same scan. Gateway injection must not copy the canary into a frame.

## CI-B, KVM

Do not mount the guest workspace or rootfs on the host to search it.
`secret-probe` inside the guest is the guest filesystem oracle. The host
scans the terminal capture, the export bundle, and the runner logs with
the helper, then `--require-probe` on the terminal capture. A probe that
cannot run (mock exit 5, or no probe line) fails the lane. Fakes do not
satisfy this lane. Missing `/dev/kvm` fails it visibly.

For a future qualified RAM mode, plant the canary in the same tmpfs file
as the stand-in access token (`/run/jeryu/provider-access`). The probe may
see it in that file only in a test that is asserting RAM delivery. The
export, the frames, and the logs must still be clean, and the workspace
copy of the canary must be absent. Helper-mode tests never plant the
canary in the guest. A helper-mode `present` result is a failure.

## Review

A PR that waives this helper, stubs it to always print `absent`, or points
it at an empty directory does not pass. A green gitleaks or Jankurai result
that was skipped or replaced does not pass either. This oracle is not a
substitute for those gates.
