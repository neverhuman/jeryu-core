# mock-agent-v1

One test binary, `jeryu-mock-agent`. `argv[0]` basename selects the
provider: `mock-claude`, `mock-codex`, or `mock-grok`. Any other basename
exits 2 with `unknown_mock_agent`. Install it with those three names
(hard links or symlinks). `argv[1]` is the mode. If `JERYU_MOCK_AGENT_MODE`
is set it must equal `argv[1]` or be the only mode source. A conflict
exits 2.

The binary is test-signed and ships only in a test rootfs. It is not a
production profile. The three names share every mode. The provider only
changes identity checks.

Modes that print a banner print one first line,
`mock-agent provider=<name> mode=<mode>`. `cpr`, `flood`, and
`secret-probe` do not print that banner.

| Mode | Behavior | Exit |
| --- | --- | --- |
| `cpr` | Write the four bytes ESC `[` `6` `n` to stdout. Read stdin for 2 seconds. Succeed when a CPR reply matches ESC `[` digits `;` digits `R`. Do not answer the query. | 0 on a reply, 3 on timeout |
| `flood` | Write 2 MiB of ASCII `x` to stdout. | 0 |
| `hang` | Sleep up to one hour. No SIGINT handler, so SIGINT kills it. SIGTERM ends it. | 0 on SIGTERM |
| `ignore-sigint` | Ignore SIGINT. On each SIGINT write one line `SIGINT_IGNORED`. Exit on SIGTERM. | 0 |
| `background-child` | Fork. The child calls `setsid`, keeps the PTY open, and sleeps. The parent exits at once. | parent 0 |
| `edit-build-commit` | In a git checkout, write `mock-agent.txt`, `git add` it, and commit with author `mock-agent <mock@jeryu.invalid>` and message `mock-agent edit`. If `cc` is on `PATH`, also compile `int main(void){return 0;}` from `mock-agent.c` to `mock-agent.bin`. If `cc` is absent, skip the compile. | 0, or 4 if git or an attempted compile fails |
| `secret-probe` | Search process environment, argv, and files under `.`, `$HOME`, `/workspace`, `/tmp`, `/run`, and `/etc` when those directories exist. Do not search `/proc`. Do not follow symlinks. Skip files larger than 1 MiB. Look for the byte prefix `jeryu-canary-`. Do not print a match and do not copy it. Print one line only. | 0, or 5 if the search cannot run |

`secret-probe` output is exactly `LEAK_ORACLE_PROBE=absent` or
`LEAK_ORACLE_PROBE=present`. CI treats a missing line as a failure. A
`present` line fails the oracle even when the canary itself was not copied
into the terminal.

CI-A runs these modes on a PTY in the fake guest. The `cpr` mode is how
that lane checks the headless VT: the VT must answer, or the mode exits 3.
CI-B runs the same binary inside Firecracker. A missing `/dev/kvm` fails
the lane. The fake guest cannot satisfy CI-B.

These modes do not prove a real Claude, Codex, or Grok CLI.
