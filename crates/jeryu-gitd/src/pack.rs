//! Pack protocol adapters.

use crate::command::{run_capture, run_with_stdin};
use crate::error::{GitdError, Result};
use crate::repo::Repository;

const MAIN_REF: &str = "refs/heads/main";

/// Git pack service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackService {
    /// `git-upload-pack`.
    UploadPack,
    /// `git-receive-pack`.
    ReceivePack,
}

impl PackService {
    /// HTTP service name.
    #[must_use]
    pub fn http_name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    /// Whether the service mutates the repository (receive-pack / push).
    #[must_use]
    pub fn is_write(self) -> bool {
        matches!(self, Self::ReceivePack)
    }

    /// Git subcommand.
    #[must_use]
    pub fn git_subcommand(self) -> &'static str {
        match self {
            Self::UploadPack => "upload-pack",
            Self::ReceivePack => "receive-pack",
        }
    }

    /// Parse a service name.
    #[must_use]
    pub fn parse(service: &str) -> Option<Self> {
        match service {
            "git-upload-pack" => Some(Self::UploadPack),
            "git-receive-pack" => Some(Self::ReceivePack),
            _ => None,
        }
    }
}

/// Advertise refs for smart HTTP.
pub fn advertise_refs(git_bin: &str, repo: &Repository, service: PackService) -> Result<Vec<u8>> {
    let path = repo.path.to_string_lossy().to_string();
    let command = service.git_subcommand();
    let out = run_capture(
        git_bin,
        &[command, "--stateless-rpc", "--advertise-refs", &path],
        None,
    )?;
    Ok(out.stdout)
}

/// Execute a stateless RPC exchange.
pub fn stateless_rpc(
    git_bin: &str,
    repo: &Repository,
    service: PackService,
    body: &[u8],
) -> Result<Vec<u8>> {
    let path = repo.path.to_string_lossy().to_string();
    let command = service.git_subcommand();
    let out = run_with_stdin(git_bin, &[command, "--stateless-rpc", &path], body, None)?;
    Ok(out.stdout)
}

/// A receive-pack ref update command from the request prelude.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivePackCommand {
    /// Previous oid supplied by the client.
    pub old_oid: String,
    /// New oid supplied by the client.
    pub new_oid: String,
    /// Ref name supplied by the client.
    pub ref_name: String,
}

/// Parse receive-pack update commands from a stateless request body.
///
/// The receive-pack request starts with pkt-line command records, then a flush,
/// then raw packfile bytes. This parser deliberately stops at the first flush so
/// it never attempts to pkt-line decode the packfile payload.
pub fn receive_pack_commands(mut input: &[u8]) -> Result<Vec<ReceivePackCommand>> {
    let mut commands = Vec::new();
    let mut first_command = true;
    while !input.is_empty() {
        if input.len() < 4 {
            return Err(GitdError::Protocol("pkt-line missing length".to_string()));
        }
        let hdr = std::str::from_utf8(&input[..4])
            .map_err(|_| GitdError::Protocol("pkt-line length is not utf8".to_string()))?;
        let len = usize::from_str_radix(hdr, 16)
            .map_err(|_| GitdError::Protocol(format!("invalid pkt-line length: {hdr}")))?;
        input = &input[4..];
        match len {
            0 => break,
            1 | 2 => continue,
            3 => {
                return Err(GitdError::Protocol(
                    "reserved pkt-line length 0003".to_string(),
                ));
            }
            n => {
                let payload_len = n
                    .checked_sub(4)
                    .ok_or_else(|| GitdError::Protocol("pkt-line underflow".to_string()))?;
                if input.len() < payload_len {
                    return Err(GitdError::Protocol(
                        "pkt-line payload truncated".to_string(),
                    ));
                }
                let mut payload = &input[..payload_len];
                input = &input[payload_len..];
                if first_command {
                    if let Some(capabilities) = payload.iter().position(|b| *b == 0) {
                        payload = &payload[..capabilities];
                    }
                    first_command = false;
                }
                let line = String::from_utf8_lossy(payload);
                let line = line.trim_end_matches('\n');
                let mut parts = line.split_whitespace();
                let Some(old_oid) = parts.next() else {
                    return Err(GitdError::Protocol(
                        "receive-pack command missing old oid".to_string(),
                    ));
                };
                let Some(new_oid) = parts.next() else {
                    return Err(GitdError::Protocol(
                        "receive-pack command missing new oid".to_string(),
                    ));
                };
                let Some(ref_name) = parts.next() else {
                    return Err(GitdError::Protocol(
                        "receive-pack command missing ref name".to_string(),
                    ));
                };
                commands.push(ReceivePackCommand {
                    old_oid: old_oid.to_string(),
                    new_oid: new_oid.to_string(),
                    ref_name: ref_name.to_string(),
                });
            }
        }
    }
    Ok(commands)
}

/// Enforce the PR-only trunk policy before invoking Git receive-pack.
pub fn ensure_receive_pack_policy(body: &[u8]) -> Result<()> {
    for command in receive_pack_commands(body)? {
        if command.ref_name == MAIN_REF {
            return Err(GitdError::ProtectedRefDenied(
                "direct pushes to refs/heads/main are blocked; open a pull request and merge through Jeryu".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pktline;

    #[test]
    fn receive_pack_policy_rejects_main_before_pack_payload() {
        let mut body = pktline::encode_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/main\0 report-status\n",
        );
        body.extend(pktline::flush());
        body.extend(b"PACK fake bytes that are not pkt-lines");

        let err = ensure_receive_pack_policy(&body).unwrap_err();

        assert!(err.to_string().contains("direct pushes to refs/heads/main"));
    }

    #[test]
    fn receive_pack_parser_keeps_non_main_commands() {
        let mut body = pktline::encode_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/feature\0 report-status\n",
        );
        body.extend(pktline::encode_str(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccccccccccc refs/heads/topic\n",
        ));
        body.extend(pktline::flush());
        body.extend(b"PACK");

        let commands = receive_pack_commands(&body).expect("parse receive-pack commands");

        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].ref_name, "refs/heads/feature");
        assert_eq!(commands[1].ref_name, "refs/heads/topic");
        ensure_receive_pack_policy(&body).expect("non-main updates are allowed");
    }
}
