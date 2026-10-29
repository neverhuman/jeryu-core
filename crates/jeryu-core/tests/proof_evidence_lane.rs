//! The evidence lane's own guards: where its ratchet baseline may come from,
//! and that it still refuses what it is meant to refuse.
//!
//! `ops/ci/proof_baseline.sh` is sourced and called here with a `git` stub on
//! PATH, so each refusal is executed — no forge, no network and no auditor are
//! needed. The lane itself (`ops/ci/proof_evidence.sh`) runs every Jankurai
//! tool for real and cannot be run from a unit test; what is checked of it here
//! is the wiring a reader cannot see from one file: that it is in the required
//! gate, that it takes no baseline out of the tree under test, and that no tool
//! result is ignored or stood in for.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository root above crates/jeryu-core")
        .to_path_buf()
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("jeryu_core-proof-{name}-{nanos}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Install a `git` stub whose body is `body`, and return the directory to put
/// first on PATH.
fn git_stub(dir: &Path, body: &str) -> PathBuf {
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).expect("stub bin");
    let script = format!("#!/usr/bin/env bash\nset -u\n{body}\n");
    let path = bin.join("git");
    fs::write(&path, script).expect("write git stub");
    let mode = 0o755;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod stub");
    }
    bin
}

/// Source the baseline guards and run `snippet` with `stub_bin` first on PATH.
fn run_guard(stub_bin: Option<&Path>, snippet: &str) -> Output {
    let root = repo_root();
    let base_path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    let path = match stub_bin {
        Some(bin) => format!("{}:{base_path}", bin.display()),
        None => base_path,
    };
    Command::new("bash")
        .arg("-c")
        .arg(format!("source ops/ci/proof_baseline.sh\n{snippet}"))
        .current_dir(&root)
        .env("PATH", path)
        .output()
        .expect("run guard")
}

fn lane_source() -> String {
    fs::read_to_string(repo_root().join("ops/ci/proof_evidence.sh")).expect("lane source")
}

const MAIN_COMMIT: &str = "1111111111111111111111111111111111111111";

#[test]
fn baseline_origin_must_be_a_remote_the_head_cannot_write() {
    let dir = temp_dir("origin");
    let remote = git_stub(
        &dir,
        r#"if [[ "$1 $2 $3" == "remote get-url origin" ]]; then
  printf '%s\n' "$STUB_ORIGIN"; exit 0
fi
exit 1"#,
    );

    let out = run_guard(
        Some(&remote),
        "STUB_ORIGIN=https://forge.example/jeryu/jeryu-core.git proof_baseline_remote_url",
    );
    assert!(out.status.success(), "a remote URL is the baseline source");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "https://forge.example/jeryu/jeryu-core.git"
    );

    for local in ["/home/someone/jeryu-core", "../jeryu-core", ""] {
        let out = run_guard(
            Some(&remote),
            &format!("STUB_ORIGIN={local:?} proof_baseline_remote_url"),
        );
        assert!(
            !out.status.success(),
            "a local origin ({local}) must not be trusted as the forge"
        );
    }
}

#[test]
fn a_shallow_checkout_is_deepened_before_ancestry_is_asked() {
    let dir = temp_dir("shallow");
    // A depth-1 checkout: the baseline commit is absent until a fetch brings
    // it, and `--unshallow` is the fetch that makes ancestry answerable.
    let stub = git_stub(
        &dir,
        r#"log="$STUB_LOG"
printf '%s\n' "$*" >>"$log"
case "$*" in
  "rev-parse --is-shallow-repository") [[ -e "$log.deep" ]] && printf 'false\n' || printf 'true\n'; exit 0 ;;
  "fetch --quiet --no-tags --unshallow origin main") : >"$log.deep"; exit 0 ;;
  cat-file*) [[ -e "$log.deep" ]] && exit 0 || exit 1 ;;
  "merge-base --is-ancestor"*) exit 0 ;;
esac
exit 1"#,
    );
    let log = dir.join("calls");
    let out = run_guard(
        Some(&stub),
        &format!(
            "STUB_LOG={:?} proof_baseline_require_descendant {MAIN_COMMIT} HEAD",
            log.display().to_string()
        ),
    );
    assert!(
        out.status.success(),
        "deepening then asking must pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = fs::read_to_string(&log).expect("stub log");
    let unshallow = calls
        .lines()
        .position(|l| l.contains("--unshallow"))
        .expect("the guard deepens the checkout");
    let ancestry = calls
        .lines()
        .position(|l| l.starts_with("merge-base"))
        .expect("the guard asks about ancestry");
    assert!(
        unshallow < ancestry,
        "ancestry must be asked only after the history is here: {calls}"
    );
}

#[test]
fn a_head_that_does_not_descend_from_protected_main_is_refused() {
    let dir = temp_dir("descend");
    let stub = git_stub(
        &dir,
        r#"case "$*" in
  "rev-parse --is-shallow-repository") printf 'false\n'; exit 0 ;;
  cat-file*) exit 0 ;;
  "merge-base --is-ancestor"*) exit 1 ;;
esac
exit 1"#,
    );
    let out = run_guard(
        Some(&stub),
        &format!("proof_baseline_require_descendant {MAIN_COMMIT} HEAD"),
    );
    assert!(!out.status.success(), "a stale head must fail the lane");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does not descend from protected main"),
        "the refusal says what to do: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A commit id is all the guard will pass to git: no ref name, no option.
    for bad in ["--upload-pack=touch /tmp/x", "origin/main", "1111111"] {
        let out = run_guard(
            Some(&stub),
            &format!("proof_baseline_require_descendant {bad:?} HEAD"),
        );
        assert!(!out.status.success(), "{bad} is not a commit id");
    }
}

#[test]
fn a_baseline_commit_that_never_arrives_fails_closed() {
    let dir = temp_dir("missing");
    let stub = git_stub(
        &dir,
        r#"case "$*" in
  "rev-parse --is-shallow-repository") printf 'false\n'; exit 0 ;;
  cat-file*) exit 1 ;;
  fetch*) exit 0 ;;
esac
exit 1"#,
    );
    let out = run_guard(
        Some(&stub),
        &format!("proof_baseline_require_descendant {MAIN_COMMIT} HEAD"),
    );
    assert!(
        !out.status.success(),
        "a fetch that brought nothing must not be taken for ancestry"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("is not in this checkout"));
}

#[test]
fn an_unclean_or_commitless_protected_clone_is_refused() {
    let dir = temp_dir("clone");
    let stub = git_stub(
        &dir,
        r#"case "$1" in
  clone) mkdir -p "${@: -1}"; exit 0 ;;
esac
case "$*" in
  *"rev-parse --verify HEAD^{commit}") printf '%s\n' "$STUB_HEAD"; exit 0 ;;
  *"status --porcelain=v1 --untracked-files=all") printf '%s' "$STUB_DIRTY"; exit 0 ;;
esac
exit 1"#,
    );
    let ok = run_guard(
        Some(&stub),
        &format!(
            "STUB_HEAD={MAIN_COMMIT} STUB_DIRTY= proof_baseline_clone https://forge.example/r.git {:?}",
            dir.join("a").display().to_string()
        ),
    );
    assert!(ok.status.success(), "a clean clone is the baseline");
    assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), MAIN_COMMIT);

    let dirty = run_guard(
        Some(&stub),
        &format!(
            "STUB_HEAD={MAIN_COMMIT} STUB_DIRTY=' M agent/audit-policy.toml' proof_baseline_clone https://forge.example/r.git {:?}",
            dir.join("b").display().to_string()
        ),
    );
    assert!(
        !dirty.status.success(),
        "a dirty clone is not protected main"
    );

    let short = run_guard(
        Some(&stub),
        &format!(
            "STUB_HEAD=1111111 STUB_DIRTY= proof_baseline_clone https://forge.example/r.git {:?}",
            dir.join("c").display().to_string()
        ),
    );
    assert!(
        !short.status.success(),
        "an abbreviated head is not a commit id"
    );
}

#[test]
fn the_head_may_not_edit_the_policy_that_judges_it() {
    let dir = temp_dir("policy");
    let candidate = dir.join("candidate.toml");
    let protected = dir.join("protected.toml");
    fs::write(&candidate, "minimum_score = 85\n").expect("write candidate");
    fs::write(&protected, "minimum_score = 85\n").expect("write protected");
    let same = run_guard(
        None,
        &format!(
            "proof_baseline_require_policy_identity {:?} {:?}",
            candidate.display().to_string(),
            protected.display().to_string()
        ),
    );
    assert!(same.status.success(), "the same policy judges both sides");

    fs::write(&candidate, "minimum_score = 10\n").expect("rewrite candidate");
    let drifted = run_guard(
        None,
        &format!(
            "proof_baseline_require_policy_identity {:?} {:?}",
            candidate.display().to_string(),
            protected.display().to_string()
        ),
    );
    assert!(
        !drifted.status.success(),
        "a head that lowers the floor must not be judged by its own policy"
    );

    let missing = run_guard(
        None,
        &format!(
            "proof_baseline_require_policy_identity {:?} {:?}",
            dir.join("absent.toml").display().to_string(),
            protected.display().to_string()
        ),
    );
    assert!(!missing.status.success(), "a missing policy fails closed");
}

#[test]
fn the_lane_keeps_no_baseline_and_no_result_it_did_not_produce() {
    let lane = lane_source();
    assert!(
        !lane.contains("|| true"),
        "no tool in the lane may have its failure discarded"
    );
    assert!(
        !lane.contains("agent/baselines"),
        "the ratchet baseline may not come from a file in the tree under test"
    );
    assert!(
        lane.contains("proof_baseline_clone"),
        "the baseline comes from the forge's copy of protected main"
    );
    assert!(
        lane.contains("proof_baseline_require_policy_identity"),
        "the lane checks that main's policy judges this head"
    );
    // Every write into target/ is a tool's own output or the summary of this
    // run; a `printf > target/...` fallback would be a result nobody produced.
    for line in lane.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.contains("> target/") {
            continue;
        }
        assert!(
            line.starts_with("> \"target/jankurai/proof-evidence-summary.json\""),
            "the lane synthesizes an artifact: {line}"
        );
    }
    assert!(
        lane.contains("migration-report.json") && lane.contains("liability_score <= $baseline"),
        "the migration analysis result is gated, not merely written"
    );
    // The only commands the lane names without running are the two whose runner
    // needs the jankurai crate in this workspace. Anything else named for the
    // adoption detector and not run would be evidence of a tool that never ran.
    let catalog: Vec<&str> = lane
        .lines()
        .map(str::trim_end)
        .filter(|line| line.starts_with("#   "))
        .collect();
    assert_eq!(
        catalog,
        vec![
            "#   cargo run -p jankurai -- copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md",
            "#   cargo test -p jankurai --test language_bad_behavior",
        ],
        "the lane names a command for adoption detection that it does not run"
    );
    assert!(
        lane.contains("needs a clean checkout"),
        "the lane refuses a tree that is not the head it reports on"
    );
}

#[test]
fn the_required_gate_runs_the_lane() {
    let pr_ci = fs::read_to_string(repo_root().join("ops/ci/pr-ci.sh")).expect("pr-ci.sh");
    let invocation = pr_ci
        .lines()
        .find(|line| line.trim() == "bash ops/ci/proof_evidence.sh")
        .is_some();
    assert!(
        invocation,
        "ops/ci/pr-ci.sh must run the evidence lane unconditionally"
    );
    let workflow =
        fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).expect("ci.yml");
    assert!(
        workflow.contains("bash ops/ci/proof_evidence.sh"),
        "the mirrored workflow runs the same lane"
    );
}
