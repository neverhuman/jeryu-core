//! External command execution with explicit error handling.

use crate::error::{GitdError, Result};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

const MAX_STREAM_STDERR_BYTES: usize = 64 * 1024;

/// Output captured from a command.
#[derive(Debug)]
pub struct CommandOutput {
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error text.
    pub stderr: String,
}

/// Spawned command whose standard input and output are pumped without
/// collecting either stream in memory.
#[derive(Debug)]
pub(crate) struct StreamingCommand {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    display: String,
    finished: bool,
}

impl StreamingCommand {
    /// Pump exactly `expected_stdin_bytes` from `input` into the child while
    /// concurrently copying child stdout into `output`.
    ///
    /// Concurrent pumping prevents the child and client from deadlocking when
    /// both sides apply backpressure. Stderr is fully drained but only a
    /// bounded prefix is retained for a failure diagnostic.
    pub(crate) fn pump<R: Read + Send, W: Write>(
        mut self,
        mut input: R,
        mut output: W,
        expected_stdin_bytes: u64,
    ) -> Result<()> {
        let mut stdin = self
            .stdin
            .take()
            .ok_or_else(|| GitdError::Protocol("streaming command stdin missing".to_string()))?;
        let mut stdout = self
            .stdout
            .take()
            .ok_or_else(|| GitdError::Protocol("streaming command stdout missing".to_string()))?;
        let stderr = self
            .stderr
            .take()
            .ok_or_else(|| GitdError::Protocol("streaming command stderr missing".to_string()))?;

        let pump_result = std::thread::scope(|scope| {
            let stdin_thread = scope.spawn(move || io::copy(&mut input, &mut stdin));
            let stderr_thread = scope.spawn(move || read_bounded_stderr(stderr));
            let stdout_result = io::copy(&mut stdout, &mut output);
            let stdin_result = stdin_thread
                .join()
                .map_err(|_| io::Error::other("streaming stdin pump panicked"))?;
            let stderr_result = stderr_thread
                .join()
                .map_err(|_| io::Error::other("streaming stderr pump panicked"))?;
            Ok::<_, io::Error>((stdin_result, stdout_result, stderr_result))
        });

        let status = self.child.wait()?;
        self.finished = true;
        let (stdin_result, stdout_result, stderr_result) = pump_result?;
        let stdin_bytes = stdin_result?;
        stdout_result?;
        let stderr = stderr_result?;
        if stdin_bytes != expected_stdin_bytes {
            return Err(GitdError::Protocol(format!(
                "request body truncated: expected {expected_stdin_bytes} bytes, received {stdin_bytes}"
            )));
        }
        if !status.success() {
            return Err(GitdError::GitCommandFailed {
                program: self.display.clone(),
                code: status.code(),
                stderr,
            });
        }
        Ok(())
    }
}

impl Drop for StreamingCommand {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Run a command and capture output.
pub fn run_capture(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<CommandOutput> {
    run_capture_with_env(program, args, cwd, &[])
}

/// Run a command with an explicit environment overlay and capture output.
pub(crate) fn run_capture_with_env(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env: &[(&str, &str)],
) -> Result<CommandOutput> {
    let mut cmd = Command::new(program);
    cmd.args(args).envs(env.iter().copied());
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(GitdError::GitCommandFailed {
            program: format!("{} {}", program, args.join(" ")),
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    Ok(CommandOutput {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    })
}

/// Run a command with bytes on stdin and capture output.
pub fn run_with_stdin(
    program: &str,
    args: &[&str],
    stdin: &[u8],
    cwd: Option<&Path>,
) -> Result<CommandOutput> {
    run_with_stdin_with_env(program, args, stdin, cwd, &[])
}

/// Run a command with bytes on stdin, an explicit environment overlay, and
/// captured output.
pub(crate) fn run_with_stdin_with_env(
    program: &str,
    args: &[&str],
    stdin: &[u8],
    cwd: Option<&Path>,
    env: &[(&str, &str)],
) -> Result<CommandOutput> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let mut child = cmd.spawn()?;
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(GitdError::GitCommandFailed {
            program: format!("{} {}", program, args.join(" ")),
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    Ok(CommandOutput {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    })
}

/// Spawn a streaming command with an explicit environment overlay.
pub(crate) fn spawn_streaming_with_env(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env: &[(&str, &str)],
) -> Result<StreamingCommand> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let mut child = cmd.spawn()?;
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    Ok(StreamingCommand {
        child,
        stdin,
        stdout,
        stderr,
        display: format!("{} {}", program, args.join(" ")),
        finished: false,
    })
}

fn read_bounded_stderr(mut stderr: ChildStderr) -> io::Result<String> {
    let mut retained = Vec::with_capacity(MAX_STREAM_STDERR_BYTES);
    let mut truncated = false;
    let mut chunk = [0u8; 8192];
    loop {
        let read = stderr.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_STREAM_STDERR_BYTES.saturating_sub(retained.len());
        let keep = remaining.min(read);
        retained.extend_from_slice(&chunk[..keep]);
        truncated |= keep < read;
    }
    let mut text = String::from_utf8_lossy(&retained).to_string();
    if truncated {
        text.push_str("\n[stderr truncated]");
    }
    Ok(text)
}

/// Replace the current process with a git service command on Unix, or run it on
/// non-Unix platforms.
pub fn exec_or_run(program: &str, args: &[&str]) -> Result<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(program).args(args).exec();
        Err(GitdError::Io(err))
    }
    #[cfg(not(unix))]
    {
        let status = Command::new(program).args(args).status()?;
        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RepeatingReader {
        remaining: usize,
        byte: u8,
        max_chunk: usize,
    }

    impl Read for RepeatingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.remaining.min(buffer.len()).min(self.max_chunk);
            buffer[..count].fill(self.byte);
            self.remaining -= count;
            Ok(count)
        }
    }

    struct FragmentedWriter {
        bytes: u64,
        max_chunk: usize,
    }

    impl Write for FragmentedWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let count = buffer.len().min(self.max_chunk);
            self.bytes += count as u64;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn streaming_command_pumps_large_input_without_collecting_it() {
        let input_bytes = 8 * 1024 * 1024;
        let process = spawn_streaming_with_env("git", &["hash-object", "--stdin"], None, &[])
            .unwrap_or_else(|err| panic!("spawn git hash-object: {err}"));
        let input = RepeatingReader {
            remaining: input_bytes,
            byte: b'x',
            max_chunk: 113,
        };
        let mut output = Vec::new();

        process
            .pump(input, &mut output, input_bytes as u64)
            .unwrap_or_else(|err| panic!("stream git hash-object: {err}"));

        assert_eq!(output.len(), 41);
        assert_eq!(output.last(), Some(&b'\n'));
    }

    #[test]
    fn streaming_command_rejects_truncated_input() {
        let process = spawn_streaming_with_env("git", &["hash-object", "--stdin"], None, &[])
            .unwrap_or_else(|err| panic!("spawn git hash-object: {err}"));
        let mut output = Vec::new();

        let err = process
            .pump(&b"short"[..], &mut output, 99)
            .expect_err("short input must be rejected");

        assert!(err.to_string().contains("request body truncated"));
    }

    #[test]
    fn streaming_command_honors_fragmented_output_backpressure() {
        let input_bytes = 8 * 1024 * 1024;
        let process = spawn_streaming_with_env("cat", &[], None, &[])
            .unwrap_or_else(|err| panic!("spawn cat: {err}"));
        let input = RepeatingReader {
            remaining: input_bytes,
            byte: b'z',
            max_chunk: 113,
        };
        let mut output = FragmentedWriter {
            bytes: 0,
            max_chunk: 127,
        };

        process
            .pump(input, &mut output, input_bytes as u64)
            .unwrap_or_else(|err| panic!("stream cat: {err}"));

        assert_eq!(output.bytes, input_bytes as u64);
    }
}
