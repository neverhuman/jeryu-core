use super::*;
use crate::{GitdConfig, RepoId};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn smart_http_splits_query() {
    let (path, query) = split_path_query("/acme/demo.git/info/refs?service=git-upload-pack");
    assert_eq!(path, "/acme/demo.git/info/refs");
    assert_eq!(query.get("service"), Some(&"git-upload-pack".to_string()));
}

#[test]
fn git_protocol_header_is_closed_to_supported_versions() {
    let mut request = HttpRequest {
        method: "GET".to_string(),
        path: "/acme/demo.git/info/refs".to_string(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: Vec::new(),
        is_loopback: false,
        auth_prechecked: false,
    };
    assert_eq!(git_protocol_header(&request).expect("v0"), None);
    request
        .headers
        .insert("git-protocol".to_string(), "version=2".to_string());
    assert_eq!(
        git_protocol_header(&request).expect("v2"),
        Some("version=2")
    );
    request
        .headers
        .insert("git-protocol".to_string(), "version=3".to_string());
    assert!(git_protocol_header(&request).is_err());
}

#[test]
fn production_socket_sends_error_before_headers_when_git_spawn_fails() {
    let root = temp_dir("jeryu-streaming-spawn-failure");
    let manager = RepoManager::new(GitdConfig::new(&root));
    manager
        .create_bare(&RepoId::new("acme", "broken").expect("valid repo id"))
        .expect("create bare repository");
    let mut config = GitdConfig::new(&root);
    config.git_bin = "/definitely/not/a/git-binary".to_string();
    let (base_url, stop, server_thread) =
        start_test_server(SmartHttpServer::new(RepoManager::new(config)));
    let address = base_url.trim_start_matches("http://");
    let mut client = TcpStream::connect(address).expect("connect test client");
    client
        .write_all(
            b"POST /acme/broken.git/git-upload-pack HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n0000",
        )
        .expect("write request");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("finish request");
    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");
    stop.store(true, Ordering::Release);
    server_thread.join().expect("server thread joins");

    assert!(response.starts_with("HTTP/1.1 500"), "{response}");
    assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn production_socket_honors_expect_continue_before_reading_rpc_body() {
    let root = temp_dir("jeryu-streaming-expect-continue");
    let manager = RepoManager::new(GitdConfig::new(&root));
    manager
        .create_bare(&RepoId::new("acme", "continue").expect("valid repo id"))
        .expect("create bare repository");
    let (base_url, stop, server_thread) = start_test_server(SmartHttpServer::new(manager));
    let address = base_url.trim_start_matches("http://");
    let mut client = TcpStream::connect(address).expect("connect test client");
    client
        .write_all(
            b"POST /acme/continue.git/git-upload-pack HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n",
        )
        .expect("write request head");
    let mut informational = [0u8; 25];
    client
        .read_exact(&mut informational)
        .expect("read continue response");
    assert_eq!(&informational, b"HTTP/1.1 100 Continue\r\n\r\n");
    client.write_all(b"0000").expect("write request body");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("finish request");
    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");
    stop.store(true, Ordering::Release);
    server_thread.join().expect("server thread joins");

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn production_socket_streams_clone_fetch_and_push_v0_and_v2() {
    for protocol in ["0", "2"] {
        exercise_streaming_protocol(protocol);
        exercise_shallow_push(protocol);
    }
}

fn exercise_streaming_protocol(protocol: &str) {
    if Command::new("git")
        .arg("--version")
        .output()
        .map(|output| !output.status.success())
        .unwrap_or(true)
    {
        return;
    }
    let root = temp_dir("jeryu-streaming-http-root");
    let seed = temp_dir("jeryu-streaming-http-seed");
    let clone = temp_dir("jeryu-streaming-http-clone");
    let manager = RepoManager::new(GitdConfig::new(&root));
    let repo = manager
        .create_bare(&RepoId::new("acme", "streamed").expect("valid repo id"))
        .expect("create bare repository");
    seed_repository(&seed, &repo.path);

    let (base_url, stop, server_thread) = start_test_server(SmartHttpServer::new(manager));
    let remote = format!("{base_url}/acme/streamed.git");
    let protocol_config = format!("protocol.version={protocol}");
    run_command(
        Command::new("git")
            .args(["-c", &protocol_config, "clone", "--branch", "main"])
            .arg(&remote)
            .arg(&clone),
        "streaming HTTP clone",
    );
    run_git(
        &clone,
        &["config", "user.email", "stream@example.invalid"],
        "clone email",
    );
    run_git(
        &clone,
        &["config", "user.name", "Streaming Test"],
        "clone name",
    );
    run_git(&clone, &["checkout", "-b", "topic"], "topic checkout");
    std::fs::write(clone.join("topic.txt"), "streamed push\n").expect("write topic");
    run_git(&clone, &["add", "topic.txt"], "topic add");
    run_git(&clone, &["commit", "-m", "topic"], "topic commit");
    run_command(
        Command::new("git")
            .args([
                "-c",
                &protocol_config,
                "-c",
                "http.postBuffer=10485760",
                "push",
                "origin",
                "HEAD:refs/heads/topic",
            ])
            .current_dir(&clone),
        "streaming HTTP push",
    );

    std::fs::write(seed.join("upstream.txt"), "streamed fetch\n").expect("write upstream");
    run_git(&seed, &["add", "upstream.txt"], "upstream add");
    run_git(&seed, &["commit", "-m", "upstream"], "upstream commit");
    run_git(
        &seed,
        &[
            "push",
            repo.path.to_str().unwrap_or_default(),
            "HEAD:refs/heads/main",
        ],
        "upstream direct push",
    );
    run_command(
        Command::new("git")
            .args(["-c", &protocol_config, "fetch", "origin", "main"])
            .current_dir(&clone),
        "streaming HTTP fetch",
    );

    stop.store(true, Ordering::Release);
    server_thread.join().expect("server thread joins");
    assert_eq!(
        git_output(&repo.path, &["rev-parse", "refs/heads/topic"]),
        git_output(&clone, &["rev-parse", "HEAD"])
    );
    assert_eq!(
        git_output(&repo.path, &["rev-parse", "refs/heads/main"]),
        git_output(&clone, &["rev-parse", "FETCH_HEAD"])
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(seed);
    let _ = std::fs::remove_dir_all(clone);
}

fn exercise_shallow_push(protocol: &str) {
    if Command::new("git")
        .arg("--version")
        .output()
        .map(|output| !output.status.success())
        .unwrap_or(true)
    {
        return;
    }
    let root = temp_dir("jeryu-shallow-http-root");
    let seed = temp_dir("jeryu-shallow-http-seed");
    let clone = temp_dir("jeryu-shallow-http-clone");
    let manager = RepoManager::new(GitdConfig::new(&root));
    let repo = manager
        .create_bare(&RepoId::new("acme", "shallow").expect("valid repo id"))
        .expect("create bare repository");
    seed_repository(&seed, &repo.path);
    for revision in 1..=2 {
        std::fs::write(seed.join("history.txt"), format!("revision {revision}\n"))
            .expect("write history");
        run_git(&seed, &["add", "history.txt"], "history add");
        run_git(
            &seed,
            &["commit", "-m", &format!("history {revision}")],
            "history commit",
        );
        run_git(
            &seed,
            &[
                "push",
                repo.path.to_str().unwrap_or_default(),
                "HEAD:refs/heads/main",
            ],
            "history direct push",
        );
    }
    let protected_main = git_output(&repo.path, &["rev-parse", "refs/heads/main"]);

    let (base_url, stop, server_thread) = start_test_server(SmartHttpServer::new(manager));
    let remote = format!("{base_url}/acme/shallow.git");
    let protocol_config = format!("protocol.version={protocol}");
    run_command(
        Command::new("git")
            .args([
                "-c",
                &protocol_config,
                "clone",
                "--depth",
                "1",
                "--branch",
                "main",
            ])
            .arg(&remote)
            .arg(&clone),
        "shallow HTTP clone",
    );
    assert_eq!(
        git_output(&clone, &["rev-parse", "--is-shallow-repository"]),
        "true"
    );
    run_git(
        &clone,
        &["config", "user.email", "shallow@example.invalid"],
        "shallow clone email",
    );
    run_git(
        &clone,
        &["config", "user.name", "Shallow Test"],
        "shallow clone name",
    );
    run_git(
        &clone,
        &["checkout", "-b", "shallow-topic"],
        "topic checkout",
    );
    std::fs::write(clone.join("topic.txt"), "shallow push\n").expect("write topic");
    run_git(&clone, &["add", "topic.txt"], "topic add");
    run_git(&clone, &["commit", "-m", "shallow topic"], "topic commit");
    run_command(
        Command::new("git")
            .args([
                "-c",
                &protocol_config,
                "-c",
                "http.postBuffer=10485760",
                "push",
                "origin",
                "HEAD:refs/heads/shallow-topic",
            ])
            .current_dir(&clone),
        "shallow HTTP push",
    );

    stop.store(true, Ordering::Release);
    server_thread.join().expect("server thread joins");
    assert_eq!(
        git_output(&repo.path, &["rev-parse", "refs/heads/shallow-topic"]),
        git_output(&clone, &["rev-parse", "HEAD"])
    );
    assert_eq!(
        git_output(&repo.path, &["rev-parse", "refs/heads/main"]),
        protected_main
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(seed);
    let _ = std::fs::remove_dir_all(clone);
}

fn start_test_server(server: SmartHttpServer) -> (String, Arc<AtomicBool>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let address = listener.local_addr().expect("listener address");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => server
                    .handle_stream(stream)
                    .unwrap_or_else(|err| panic!("test server request failed: {err}")),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("test listener failed: {err}"),
            }
        }
    });
    (format!("http://{address}"), stop, handle)
}

fn seed_repository(work: &Path, remote: &Path) {
    run_git(work, &["init"], "seed init");
    run_git(
        work,
        &["config", "user.email", "stream@example.invalid"],
        "seed email",
    );
    run_git(
        work,
        &["config", "user.name", "Streaming Test"],
        "seed name",
    );
    std::fs::write(work.join("README.md"), "streaming smart HTTP\n").expect("write seed readme");
    run_git(work, &["add", "README.md"], "seed add");
    run_git(work, &["commit", "-m", "seed"], "seed commit");
    run_git(
        work,
        &[
            "push",
            remote.to_str().unwrap_or_default(),
            "HEAD:refs/heads/main",
        ],
        "seed direct push",
    );
}

fn run_git(work: &Path, args: &[&str], label: &str) {
    run_command(Command::new("git").args(args).current_dir(work), label);
}

fn run_command(command: &mut Command, label: &str) {
    let output = command
        .output()
        .unwrap_or_else(|err| panic!("{label} failed to start: {err}"));
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output(work: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(work)
        .output()
        .expect("git output starts");
    assert!(output.status.success(), "git output failed");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn temp_dir(prefix: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("{prefix}-{stamp}-{serial}"));
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

#[derive(Debug, Default)]
struct RecordingObserver(std::sync::Mutex<Vec<String>>);

impl crate::PushObserver for RecordingObserver {
    fn repository_pushed(&self, repo: &RepoId, _at: SystemTime) {
        self.0.lock().expect("observer lock").push(repo.to_string());
    }
}

impl RecordingObserver {
    fn seen(&self) -> Vec<String> {
        self.0.lock().expect("observer lock").clone()
    }
}

#[test]
fn receive_pack_records_successful_push_but_not_rejected_push() {
    if Command::new("git")
        .arg("--version")
        .output()
        .map(|output| !output.status.success())
        .unwrap_or(true)
    {
        return;
    }
    let root = temp_dir("jeryu-pushed-at-root");
    let seed = temp_dir("jeryu-pushed-at-seed");
    let clone = temp_dir("jeryu-pushed-at-clone");
    let observer = Arc::new(RecordingObserver::default());
    let manager = RepoManager::new(GitdConfig::new(&root)).with_push_observer(observer.clone());
    let repo = manager
        .create_bare(&RepoId::new("acme", "pushed").expect("valid repo id"))
        .expect("create bare repository");
    seed_repository(&seed, &repo.path);
    manager
        .install_pre_receive_hook(&repo)
        .expect("install pre-receive hook");
    assert_eq!(crate::push::read_push_marker(&repo).expect("marker"), None);

    let (base_url, stop, server_thread) = start_test_server(SmartHttpServer::new(manager.clone()));
    let remote = format!("{base_url}/acme/pushed.git");
    run_command(
        Command::new("git")
            .args(["clone", "--branch", "main"])
            .arg(&remote)
            .arg(&clone),
        "clone",
    );
    run_git(
        &clone,
        &["config", "user.email", "p@example.invalid"],
        "email",
    );
    run_git(&clone, &["config", "user.name", "Push Test"], "name");
    std::fs::write(clone.join("topic.txt"), "topic\n").expect("write topic");
    run_git(&clone, &["add", "topic.txt"], "add");
    run_git(&clone, &["commit", "-m", "topic"], "commit");

    // The installed hook rejects direct pushes to main: no ref moves.
    let rejected = Command::new("git")
        .args(["push", "origin", "HEAD:refs/heads/main"])
        .current_dir(&clone)
        .output()
        .expect("rejected push runs");
    assert!(!rejected.status.success(), "main push must be rejected");
    assert!(observer.seen().is_empty(), "rejected push was recorded");
    assert_eq!(crate::push::read_push_marker(&repo).expect("marker"), None);

    run_git(
        &clone,
        &["push", "origin", "HEAD:refs/heads/topic"],
        "topic push",
    );
    stop.store(true, Ordering::Release);
    server_thread.join().expect("server thread joins");

    assert_eq!(observer.seen(), vec!["acme/pushed".to_string()]);
    assert!(
        crate::push::read_push_marker(&repo)
            .expect("marker")
            .is_some()
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(seed);
    let _ = std::fs::remove_dir_all(clone);
}

#[test]
fn ref_update_records_push_and_committer_time_backfills() {
    if Command::new("git")
        .arg("--version")
        .output()
        .map(|output| !output.status.success())
        .unwrap_or(true)
    {
        return;
    }
    let root = temp_dir("jeryu-pushed-at-refs-root");
    let seed = temp_dir("jeryu-pushed-at-refs-seed");
    let observer = Arc::new(RecordingObserver::default());
    let manager = RepoManager::new(GitdConfig::new(&root)).with_push_observer(observer.clone());
    let repo = manager
        .create_bare(&RepoId::new("acme", "refs").expect("valid repo id"))
        .expect("create bare repository");
    assert_eq!(
        manager
            .newest_committer_time("acme", "refs")
            .expect("empty"),
        None
    );
    assert_eq!(
        manager
            .newest_committer_time("acme", "absent")
            .expect("absent"),
        None
    );

    run_git(&seed, &["init"], "init");
    run_git(
        &seed,
        &["config", "user.email", "p@example.invalid"],
        "email",
    );
    run_git(&seed, &["config", "user.name", "Push Test"], "name");
    std::fs::write(seed.join("a.txt"), "a\n").expect("write");
    run_git(&seed, &["add", "a.txt"], "add");
    run_command(
        Command::new("git")
            .args(["commit", "-m", "old"])
            .env("GIT_COMMITTER_DATE", "2026-01-02T03:04:05Z")
            .current_dir(&seed),
        "old commit",
    );
    std::fs::write(seed.join("b.txt"), "b\n").expect("write");
    run_git(&seed, &["add", "b.txt"], "add");
    run_command(
        Command::new("git")
            .args(["commit", "-m", "new"])
            .env("GIT_COMMITTER_DATE", "2026-03-04T05:06:07Z")
            .current_dir(&seed),
        "new commit",
    );
    let target = repo.path.to_str().unwrap_or_default();
    run_git(
        &seed,
        &["push", target, "HEAD~1:refs/heads/main"],
        "old ref",
    );
    run_git(&seed, &["push", target, "HEAD:refs/heads/topic"], "new ref");
    assert!(observer.seen().is_empty(), "raw git pushes bypass gitd");
    assert_eq!(
        manager
            .newest_committer_time("acme", "refs")
            .expect("history"),
        Some(UNIX_EPOCH + Duration::from_secs(1_772_600_767))
    );

    let refs = crate::RefService::new(manager.clone());
    let head = git_output(&seed, &["rev-parse", "HEAD"]);
    refs.update_ref(&repo, "alice", "refs/heads/feature", &head, None)
        .expect("create feature ref");
    assert_eq!(observer.seen(), vec!["acme/refs".to_string()]);
    assert!(
        refs.update_ref(
            &repo,
            "alice",
            "refs/heads/feature",
            &head,
            Some(&"0".repeat(39))
        )
        .is_err()
    );
    assert_eq!(observer.seen().len(), 1, "failed ref update was recorded");

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(seed);
}
