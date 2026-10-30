//! The evidence lane's own guards: where its ratchet baseline may come from,
//! which change set it judges, how a policy amendment is judged, and that it
//! still refuses what it is meant to refuse.
//!
//! `ops/ci/proof_baseline.sh` is sourced and its functions are run against
//! throwaway git repositories, so each rule is executed without a forge, a
//! network or an auditor. The lane itself (`ops/ci/proof_evidence.sh`) runs
//! every Jankurai tool for real and cannot run from a unit test; what is checked
//! of it here is the wiring a reader cannot see from one file.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

const FORGE: &str = "https://git.neverhuman.org/git/jeryu/jeryu-core.git";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository root above crates/jeryu-core")
        .to_path_buf()
}

fn guards() -> PathBuf {
    repo_root().join("ops/ci/proof_baseline.sh")
}

fn with_identity(command: &mut Command) -> &mut Command {
    command
        .env("GIT_AUTHOR_NAME", "proof-test")
        .env("GIT_AUTHOR_EMAIL", "proof-test@invalid")
        .env("GIT_COMMITTER_NAME", "proof-test")
        .env("GIT_COMMITTER_EMAIL", "proof-test@invalid")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
}

/// Source the guards in `cwd` and run `snippet`.
fn guard(cwd: &Path, snippet: &str) -> Output {
    with_identity(Command::new("bash").arg("-c").arg(format!(
        "set -euo pipefail\nsource {:?}\n{snippet}",
        guards().display().to_string()
    )))
    .current_dir(cwd)
    .output()
    .expect("run guard")
}

fn ok(output: &Output) -> String {
    assert!(
        output.status.success(),
        "guard failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn refused(output: &Output, needle: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "guard passed; expected {needle:?}"
    );
    assert!(stderr.contains(needle), "expected {needle:?} in: {stderr}");
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = with_identity(Command::new("git").args(args))
        .current_dir(dir)
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn commit_file(dir: &Path, path: &str, body: &str) -> String {
    let file = dir.join(path);
    fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
    fs::write(&file, body).expect("write");
    git(dir, &["add", path]);
    git(dir, &["commit", "--quiet", "-m", path]);
    git(dir, &["rev-parse", "HEAD"])
}

/// A repository whose main has a policy, then two more commits, and a feature
/// branch forked from the first commit that changes one file.
struct Fixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    fork: String,
    tip: String,
    head: String,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    git(&repo, &["init", "--quiet", "-b", "main"]);
    let fork = commit_file(&repo, "agent/audit-policy.toml", "minimum_score = 85\n");
    commit_file(&repo, "main-only.txt", "one\n");
    let tip = commit_file(&repo, "main-only.txt", "two\n");
    git(&repo, &["update-ref", "refs/remotes/origin/main", &tip]);
    git(&repo, &["switch", "--quiet", "-c", "feature", &fork]);
    let head = commit_file(&repo, "src/change.rs", "fn change() {}\n");
    Fixture {
        _temp: temp,
        repo,
        fork,
        tip,
        head,
    }
}

#[test]
fn only_the_hosted_source_repository_may_serve_the_baseline() {
    let fx = fixture();
    let refused_urls = [
        "http://git.neverhuman.org/git/jeryu/jeryu-core.git",
        "git://git.neverhuman.org/git/jeryu/jeryu-core.git",
        "ssh://git@git.neverhuman.org/git/jeryu/jeryu-core.git",
        "git@git.neverhuman.org:jeryu/jeryu-core.git",
        "https://git.neverhuman.org.example/git/jeryu/jeryu-core.git",
        "https://github.com/neverhuman/jeryu-core.git",
        "/srv/jeryu-core.git",
    ];
    git(&fx.repo, &["remote", "add", "origin", FORGE]);
    ok(&guard(&fx.repo, "proof_require_origin"));
    for url in refused_urls {
        git(&fx.repo, &["remote", "set-url", "origin", url]);
        refused(
            &guard(&fx.repo, "proof_require_origin"),
            "not the hosted source repository",
        );
    }
    git(&fx.repo, &["remote", "remove", "origin"]);
    refused(&guard(&fx.repo, "proof_require_origin"), "no origin remote");
}

#[test]
fn a_head_behind_the_tip_is_judged_from_its_fork_point() {
    let fx = fixture();
    let fork = ok(&guard(
        &fx.repo,
        &format!("proof_fork_point {} {}", fx.tip, fx.head),
    ));
    assert_eq!(
        fork, fx.fork,
        "the change set starts where the head left main"
    );
    let out = fx.repo.join("changed");
    ok(&guard(
        &fx.repo,
        &format!("proof_changed_paths {} {} {:?}", fork, fx.head, out),
    ));
    assert_eq!(
        fs::read(&out).expect("changed"),
        b"src/change.rs\0",
        "main's own later commits are not this head's change"
    );
    assert!(!fx.repo.join("changed.unsorted").exists());
}

#[test]
fn protected_main_gating_its_own_head_is_an_empty_change_set() {
    let fx = fixture();
    let fork = ok(&guard(
        &fx.repo,
        &format!("proof_fork_point {} {}", fx.tip, fx.tip),
    ));
    assert_eq!(fork, fx.tip);
    let out = fx.repo.join("changed");
    ok(&guard(
        &fx.repo,
        &format!("proof_changed_paths {} {} {:?}", fork, fx.tip, out),
    ));
    assert!(fs::read(&out).expect("changed").is_empty());
}

#[test]
fn a_head_with_no_shared_history_is_refused() {
    let fx = fixture();
    git(&fx.repo, &["switch", "--quiet", "--orphan", "unrelated"]);
    let unrelated = commit_file(&fx.repo, "other.txt", "x\n");
    refused(
        &guard(
            &fx.repo,
            &format!("proof_fork_point {} {}", fx.tip, unrelated),
        ),
        "shares no history",
    );
}

#[test]
fn the_floor_is_the_policy_own_integer_and_never_lowered() {
    let temp = tempfile::tempdir().expect("tempdir");
    let policy = temp.path().join("audit-policy.toml");
    for (body, floor) in [
        ("minimum_score = 82\n", Some("82")),
        ("schema = 1\nminimum_score=91 # calibrated\n", Some("91")),
        ("minimum_score = 85.5\n", None),
        ("minimum_score = 85\nminimum_score = 90\n", None),
        ("hard_findings_allowed = 0\n", None),
    ] {
        fs::write(&policy, body).expect("policy");
        let output = guard(
            temp.path(),
            &format!("proof_effective_floor {:?}", policy.display().to_string()),
        );
        match floor {
            Some(floor) => assert_eq!(ok(&output), floor, "{body}"),
            None => refused(&output, "one integer minimum_score"),
        }
    }
    ok(&guard(temp.path(), "proof_require_floor_kept 85 85"));
    ok(&guard(temp.path(), "proof_require_floor_kept 86 85"));
    refused(
        &guard(temp.path(), "proof_require_floor_kept 84 85"),
        "lowers the audit floor from 85 to 84",
    );
}

#[test]
fn a_policy_variant_changes_only_the_policy_of_the_named_commit() {
    let fx = fixture();
    let policy = fx.repo.join("../amended.toml");
    fs::write(&policy, "minimum_score = 90\n").expect("policy");
    let dest = fx.repo.join("../variant");
    let variant = ok(&guard(
        &fx.repo,
        &format!(
            "proof_checkout_variant {:?} refs/remotes/origin/main {} {:?} {:?}",
            fx.repo.display().to_string(),
            fx.tip,
            dest.display().to_string(),
            policy.display().to_string()
        ),
    ));
    assert_ne!(variant, fx.tip);
    assert_eq!(git(&dest, &["rev-parse", "HEAD^"]), fx.tip);
    assert_eq!(
        git(&dest, &["diff", "--name-only", &fx.tip, &variant]),
        "agent/audit-policy.toml"
    );
    assert_eq!(
        fs::read_to_string(dest.join("agent/audit-policy.toml")).expect("read"),
        "minimum_score = 90\n"
    );

    // Without a policy it is the exact commit, checked out clean.
    let plain = fx.repo.join("../plain");
    let at = ok(&guard(
        &fx.repo,
        &format!(
            "proof_checkout_variant {:?} refs/remotes/origin/main {} {:?}",
            fx.repo.display().to_string(),
            fx.tip,
            plain.display().to_string()
        ),
    ));
    assert_eq!(at, fx.tip);

    // A ref that moved since the lane read it is refused, not followed.
    let moved = fx.repo.join("../moved");
    refused(
        &guard(
            &fx.repo,
            &format!(
                "proof_checkout_variant {:?} refs/remotes/origin/main {} {:?}",
                fx.repo.display().to_string(),
                fx.fork,
                moved.display().to_string()
            ),
        ),
        "moved during the proof lane",
    );
}

#[test]
fn only_canonical_policy_files_are_read() {
    let temp = tempfile::tempdir().expect("tempdir");
    let real = temp.path().join("policy.toml");
    fs::write(&real, "minimum_score = 85\n").expect("policy");
    let canonical = real.canonicalize().expect("canonical");
    ok(&guard(
        temp.path(),
        &format!(
            "proof_require_canonical_file {:?}",
            canonical.display().to_string()
        ),
    ));
    let link = temp.path().join("link.toml");
    std::os::unix::fs::symlink(&canonical, &link).expect("symlink");
    let hard = temp.path().join("hard.toml");
    fs::hard_link(&canonical, &hard).expect("hard link");
    for path in [link, hard] {
        refused(
            &guard(
                temp.path(),
                &format!(
                    "proof_require_canonical_file {:?}",
                    path.display().to_string()
                ),
            ),
            "canonical one-link regular file",
        );
    }
}

#[test]
fn migration_liability_may_not_rise_or_drop_lanes_at_equal_liability() {
    let temp = tempfile::tempdir().expect("tempdir");
    let report = |name: &str, root: &str, liability: u32, lanes: &[&str]| {
        let path = temp.path().join(name);
        let body = serde_json::json!({
            "schema_version": "1.0.0", "command": "jankurai migrate", "status": "complete",
            "source_root": root, "liability_score": liability, "required_proof_lanes": lanes,
        });
        fs::write(&path, body.to_string()).expect("report");
        path.display().to_string()
    };
    let base = report("base.json", "/main", 10, &["db-migration-analyze"]);
    let check = |candidate: &str| {
        guard(
            temp.path(),
            &format!("proof_require_migration {base:?} /main {candidate:?} ."),
        )
    };
    ok(&check(&report(
        "same.json",
        ".",
        10,
        &["db-migration-analyze"],
    )));
    ok(&check(&report("lower.json", ".", 9, &[])));
    refused(
        &check(&report("higher.json", ".", 11, &["db-migration-analyze"])),
        "migration liability regressed",
    );
    refused(
        &check(&report("dropped.json", ".", 10, &[])),
        "migration liability regressed",
    );
    refused(
        &check(&report("elsewhere.json", "/other", 1, &[])),
        "incomplete or not of .",
    );
}

/// Hold an exclusive flock on `lock` in a child process until it is killed.
fn hold_lock(lock: &Path) -> Child {
    let child = Command::new("flock")
        .arg("--exclusive")
        .arg(lock)
        .args(["sleep", "60"])
        .stdout(Stdio::null())
        .spawn()
        .expect("flock");
    for _ in 0..100 {
        let probe = Command::new("flock")
            .args(["--exclusive", "--nonblock"])
            .arg(lock)
            .arg("true")
            .status()
            .expect("probe");
        if !probe.success() {
            return child;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("the child never took the lock");
}

#[test]
fn the_sweep_removes_only_checkouts_no_live_run_holds() {
    let temp = tempfile::tempdir().expect("tempdir");
    let parent = temp.path().join("target");
    let dir = |name: &str| parent.join(format!("jeryu-core-proof-baseline.{name}"));
    let (live, released, fresh, aged) = (dir("live"), dir("released"), dir("fresh"), dir("aged"));
    let other = parent.join("debug");
    for path in [&live, &released, &fresh, &aged, &other] {
        fs::create_dir_all(path.join("main")).expect("dir");
    }
    fs::write(live.join(".lock"), "").expect("lock");
    fs::write(released.join(".lock"), "").expect("lock");
    // A live run that has run for longer than two hours keeps its checkout:
    // the lock, not the age, says whether it is in use.
    for path in [&live, &aged] {
        let status = Command::new("touch")
            .args(["-d", "4 hours ago"])
            .arg(path)
            .status()
            .expect("touch");
        assert!(status.success());
    }
    let mut holder = hold_lock(&live.join(".lock"));
    let swept = guard(
        temp.path(),
        &format!(
            "proof_sweep_stale {:?} jeryu-core-proof-baseline",
            parent.display().to_string()
        ),
    );
    let _ = holder.kill();
    let _ = holder.wait();
    ok(&swept);
    assert!(
        live.exists(),
        "a checkout a running lane holds is left alone"
    );
    assert!(
        !released.exists(),
        "a checkout whose run is gone is removed"
    );
    assert!(
        fresh.exists(),
        "a new checkout not yet locked is left alone"
    );
    assert!(
        !aged.exists(),
        "an unlocked checkout older than two hours is removed"
    );
    assert!(other.exists(), "the sweep touches only its own checkouts");
    ok(&guard(
        temp.path(),
        &format!(
            "proof_sweep_stale {:?} jeryu-core-proof-baseline",
            temp.path().join("absent").display().to_string()
        ),
    ));
}

fn lane_source() -> String {
    fs::read_to_string(repo_root().join("ops/ci/proof_evidence.sh")).expect("lane source")
}

fn code_lines(source: &str) -> impl Iterator<Item = &str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
}

#[test]
fn no_tool_result_is_discarded_or_stood_in_for() {
    let lane = lane_source();
    let guards = fs::read_to_string(guards()).expect("guards");
    for (name, source) in [("lane", &lane), ("guards", &guards)] {
        for line in code_lines(source) {
            for pattern in [
                "|| true",
                "|| :",
                "|| exit 0",
                "|| echo",
                "set +e",
                "|| printf '{",
                "|| return 0",
            ] {
                assert!(
                    !line.contains(pattern),
                    "{name} discards a failure with {pattern:?}: {line}"
                );
            }
        }
    }
    // Every file written into target/ by the lane itself is the summary of this
    // run; tool reports are each tool's own output.
    for line in code_lines(&lane) {
        let writes =
            line.contains("> target/") || line.contains(">target/") || line.contains("tee target/");
        if writes {
            assert_eq!(
                line, "> target/jankurai/proof-evidence-summary.json",
                "the lane synthesizes an artifact: {line}"
            );
        }
    }
    assert!(
        !lane.contains("agent/baselines"),
        "no baseline from the tree under test"
    );
}

#[test]
fn the_lane_takes_its_baseline_from_protected_main_and_judges_policy_amendments() {
    let lane = lane_source();
    for needle in [
        "proof_require_origin",
        "proof_require_history",
        "refs/remotes/origin/main",
        "proof_fork_point",
        "proof_checkout_variant \"$repo_root\" refs/remotes/origin/main \"$base_commit\"",
        "cmp -s -- \"$candidate_policy\" \"$protected_policy\"",
        "proof_require_floor_kept",
        "proof_require_migration",
        "proof_effective_floor",
        "needs a clean exact-head checkout",
    ] {
        assert!(lane.contains(needle), "the lane lost {needle:?}");
    }
    assert!(
        !lane.contains("host_floor") && !lane.contains("floor=85"),
        "the floor comes from the policy, not a constant in the lane"
    );
    assert!(
        code_lines(&lane).all(|line| !line.contains("target/jankurai/repo-score")),
        "the lane leaves score.sh's report alone and writes its ratchet elsewhere"
    );
}

#[test]
fn the_tool_adoption_catalog_is_retained_verbatim() {
    // Jankurai credits adoption by finding catalog commands in CI text; losing
    // one lowers this head's score against main's, which still has them all.
    let lane = lane_source();
    for command in [
        "jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md",
        "jankurai proofbind verify . --changed-from origin/main",
        "jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json",
        "cargo run -p jankurai -- copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md",
        "jankurai security run . --out target/jankurai/security/evidence.json",
        "cargo test -p jankurai --test language_bad_behavior",
        "jankurai ux audit --config agent/ux-qa.toml --out target/jankurai/ux-qa.json",
        "jankurai migrate . --analyze --json target/jankurai/migration-report.json",
        "jankurai rust witness build .",
        "jankurai vibe coverage --source agent/vibe-coverage.toml --tips tips/vibe_coding --json target/jankurai/vibe-coverage.json --md target/jankurai/vibe-coverage.md",
        "jankurai coverage audit . --config agent/coverage-sources.toml --json target/jankurai/coverage/coverage-audit.json --md target/jankurai/coverage/coverage-audit.md",
    ] {
        assert!(
            lane.lines().any(|line| line == format!("# {command}")),
            "catalog command missing: {command}"
        );
    }
}

#[test]
fn the_required_gate_runs_the_lane_once() {
    let pr_ci = fs::read_to_string(repo_root().join("ops/ci/pr-ci.sh")).expect("pr-ci.sh");
    assert!(
        pr_ci
            .lines()
            .any(|line| line.trim() == "bash ops/ci/proof_evidence.sh"),
        "ops/ci/pr-ci.sh must run the evidence lane unconditionally"
    );
    let workflow =
        fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).expect("ci.yml");
    assert!(workflow.contains("bash ops/ci/pr-ci.sh"));
    assert!(
        !workflow.contains("bash ops/ci/proof_evidence.sh"),
        "the mirrored workflow runs the lane through pr-ci.sh only"
    );
}

#[test]
fn candidate_auditor_declaration_matches_the_verified_governed_version() {
    let temp = tempfile::tempdir().expect("tempdir");
    let policy = temp.path().join("policy.toml");
    for (body, accepted) in [
        ("required_tool_version = \"1.7.6\"\n", true),
        ("required_tool_version = \"1.7.5\"\n", false),
        ("minimum_score = 85\n", false),
        (
            "required_tool_version = \"1.7.6\"\nrequired_tool_version = \"1.7.6\"\n",
            false,
        ),
        ("required_tool_version = \"1.7.6\n", false),
    ] {
        fs::write(&policy, body).expect("policy");
        let result = guard(
            temp.path(),
            &format!(
                "proof_require_governed_declaration {:?} 1.7.6",
                policy.display().to_string()
            ),
        );
        assert_eq!(
            result.status.success(),
            accepted,
            "{body}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let gate = fs::read_to_string(repo_root().join("ops/ci/pr-ci.sh")).expect("gate");
    assert!(gate.contains(
        "proof_require_governed_declaration agent/audit-policy.toml \"${JERYU_JANKURAI_SEMVER:?}\""
    ));
}
