//! Admission and accounting for Git pack RPCs (`upload-pack`, `receive-pack`).
//!
//! Every pack RPC runs a stock `git` child that builds or indexes a pack, so a
//! burst of clones or pushes is a burst of CPU-heavy processes. [`PackRpcGate`]
//! bounds how many run at once on the buffered smart-HTTP path
//! ([`crate::smart_http::SmartHttpServer::route`], which `jeryu serve` mounts):
//! a request beyond the limit waits up to a bounded time for a slot and is then
//! refused as busy (HTTP 503 with `Retry-After`).
//!
//! A slot covers only the `git` child's work. On the buffered path the request
//! body is already in memory and the response is returned as bytes, so no
//! client socket I/O happens while a slot is held. The streaming paths
//! ([`crate::smart_http::SmartHttpServer::serve`] and `prepare_pack_rpc`) pump
//! client sockets into and out of `git`, so they are recorded but never take a
//! slot: a stalled client must not be able to hold one. SSH sessions and ref
//! advertisement (`info/refs`) are neither bounded nor recorded here.
//!
//! Each recorded RPC leaves one structured line on stderr (the forge's
//! journal), [`PackRpcRecord`]: service, repository, bytes in and out, how long
//! it waited for a slot, how long it ran, and the outcome. Those lines tell an
//! operator whether fetch or push cost is growing, and whether the limit is the
//! bottleneck, before anything else is changed.

use crate::pack::PackService;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Environment variable: the most pack RPCs that may run at once.
pub const MAX_PACK_RPCS_ENV: &str = "JERYU_GITD_MAX_PACK_RPCS";
/// Environment variable: seconds a pack RPC waits for a free slot before it is
/// refused as busy.
pub const PACK_RPC_WAIT_SECS_ENV: &str = "JERYU_GITD_PACK_RPC_WAIT_SECS";
/// Seconds a refused client is told to wait before it retries.
pub const RETRY_AFTER_SECS: u64 = 5;

const DEFAULT_WAIT: Duration = Duration::from_secs(30);
/// The longest admission wait the environment may configure.
const MAX_WAIT: Duration = Duration::from_secs(300);

/// A bound on concurrently running pack RPCs.
#[derive(Debug)]
pub struct PackRpcGate {
    limit: usize,
    wait: Duration,
    running: Mutex<usize>,
    freed: Condvar,
}

/// A held slot; dropping it frees the slot.
#[derive(Debug)]
pub struct PackRpcPermit<'a> {
    gate: &'a PackRpcGate,
    /// How long the request waited before it got the slot.
    pub waited: Duration,
    /// Pack RPCs running once this one was admitted, itself included.
    pub running: usize,
}

/// A request refused because every slot stayed busy for the whole wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackRpcBusy {
    /// The configured limit.
    pub limit: usize,
    /// How long the request waited.
    pub waited: Duration,
}

impl PackRpcGate {
    /// A gate admitting at most `limit` (at least 1) RPCs, each waiting at most
    /// `wait` (at most 300 seconds) for a slot.
    #[must_use]
    pub fn new(limit: usize, wait: Duration) -> Self {
        Self {
            limit: limit.max(1),
            wait: wait.min(MAX_WAIT),
            running: Mutex::new(0),
            freed: Condvar::new(),
        }
    }

    /// The process-wide gate, configured once from [`MAX_PACK_RPCS_ENV`] and
    /// [`PACK_RPC_WAIT_SECS_ENV`]. Unset or unparsable, the limit is the host's
    /// available parallelism (clamped to 2..=64) and the wait 30 seconds; a
    /// configured wait is clamped to 1..=300 seconds.
    pub fn global() -> &'static Self {
        static GATE: OnceLock<PackRpcGate> = OnceLock::new();
        GATE.get_or_init(|| {
            let limit = std::env::var(MAX_PACK_RPCS_ENV)
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
                .filter(|limit| *limit > 0)
                .unwrap_or_else(default_limit);
            let wait = std::env::var(PACK_RPC_WAIT_SECS_ENV)
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map_or(DEFAULT_WAIT, |secs| Duration::from_secs(secs.clamp(1, 300)));
            Self::new(limit, wait)
        })
    }

    /// The configured limit.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Take a slot, waiting up to the gate's bound for one to free up.
    pub fn acquire(&self) -> Result<PackRpcPermit<'_>, PackRpcBusy> {
        let started = Instant::now();
        let deadline = started + self.wait;
        let mut running = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *running >= self.limit {
            let now = Instant::now();
            if now >= deadline {
                return Err(PackRpcBusy {
                    limit: self.limit,
                    waited: started.elapsed(),
                });
            }
            running = self
                .freed
                .wait_timeout(running, deadline - now)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        *running += 1;
        Ok(PackRpcPermit {
            gate: self,
            waited: started.elapsed(),
            running: *running,
        })
    }
}

impl Drop for PackRpcPermit<'_> {
    fn drop(&mut self) {
        let mut running = self
            .gate
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *running = running.saturating_sub(1);
        drop(running);
        // Wake every waiter: one woken past its own deadline gives up without
        // taking the slot, and must not leave the others asleep beside it.
        self.gate.freed.notify_all();
    }
}

fn default_limit() -> usize {
    std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .clamp(2, 64)
}

/// One pack RPC's accounting line.
#[derive(Clone, Debug)]
pub struct PackRpcRecord {
    /// `git-upload-pack` or `git-receive-pack`.
    pub service: &'static str,
    /// `owner/name`.
    pub repo: String,
    /// Request body bytes handed to `git`.
    pub bytes_in: u64,
    /// Response bytes `git` produced.
    pub bytes_out: u64,
    /// Time spent waiting for a slot.
    pub wait: Duration,
    /// Time from admission to the RPC's end.
    pub duration: Duration,
    /// Pack RPCs running when this one was admitted, itself included.
    pub running: usize,
    /// The gate's limit; 0 for a streamed RPC, which is recorded but not bounded.
    pub limit: usize,
    /// `ok`, `busy`, or `error`.
    pub outcome: &'static str,
}

impl PackRpcRecord {
    /// The record as one JSON object.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis());
        serde_json::json!({
            "event": "gitd.pack_rpc",
            "at_ms": u64::try_from(at_ms).unwrap_or(u64::MAX),
            "service": self.service,
            "repo": self.repo,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "wait_ms": duration_ms(self.wait),
            "duration_ms": duration_ms(self.duration),
            "running": self.running,
            "limit": self.limit,
            "outcome": self.outcome,
        })
    }

    /// Write the record to stderr as one line. Never fails the RPC.
    pub fn emit(&self) {
        eprintln!("{}", self.to_json());
    }
}

/// An admitted pack RPC: it holds a slot of the global gate until
/// [`Self::finish`], which frees the slot and emits the record. Dropped
/// without finishing (the RPC failed part-way), it frees the slot and records
/// an `error`.
#[derive(Debug)]
pub(crate) struct PackRpcAdmission {
    /// The held slot; `None` for an RPC that is recorded but not bounded.
    permit: Option<PackRpcPermit<'static>>,
    record: PackRpcRecord,
    started: Instant,
    open: bool,
}

impl PackRpcAdmission {
    /// End the RPC: `Some(bytes_out)` when it succeeded, `None` when it failed.
    pub(crate) fn finish(mut self, bytes_out: Option<u64>) {
        self.close(bytes_out);
    }

    fn close(&mut self, bytes_out: Option<u64>) {
        if !std::mem::take(&mut self.open) {
            return;
        }
        self.record.duration = self.started.elapsed();
        drop(self.permit.take());
        match bytes_out {
            Some(bytes) => {
                self.record.bytes_out = bytes;
                self.record.outcome = "ok";
            }
            None => self.record.outcome = "error",
        }
        self.record.emit();
    }
}

impl Drop for PackRpcAdmission {
    fn drop(&mut self) {
        self.close(None);
    }
}

fn new_record(
    gate: &PackRpcGate,
    service: PackService,
    repo: &str,
    bytes_in: u64,
) -> PackRpcRecord {
    PackRpcRecord {
        service: service.http_name(),
        repo: repo.to_string(),
        bytes_in,
        bytes_out: 0,
        wait: Duration::ZERO,
        duration: Duration::ZERO,
        running: 0,
        limit: gate.limit(),
        outcome: "busy",
    }
}

/// Record one streamed RPC of `service` on `repo` without taking a slot: its
/// pump copies client sockets, which a slot must never wait on.
pub(crate) fn record_streamed(
    gate: &PackRpcGate,
    service: PackService,
    repo: &str,
    bytes_in: u64,
) -> PackRpcAdmission {
    let mut record = new_record(gate, service, repo, bytes_in);
    record.limit = 0;
    PackRpcAdmission {
        permit: None,
        record,
        started: Instant::now(),
        open: true,
    }
}

/// Take a slot of `gate` for one RPC of `service` on `repo`. A request refused
/// as busy is recorded here and answered with [`crate::error::GitdError::Busy`].
pub(crate) fn admit(
    gate: &'static PackRpcGate,
    service: PackService,
    repo: &str,
    bytes_in: u64,
) -> crate::error::Result<PackRpcAdmission> {
    let mut record = new_record(gate, service, repo, bytes_in);
    match gate.acquire() {
        Ok(permit) => {
            record.wait = permit.waited;
            record.running = permit.running;
            Ok(PackRpcAdmission {
                permit: Some(permit),
                record,
                started: Instant::now(),
                open: true,
            })
        }
        Err(busy) => {
            record.wait = busy.waited;
            record.emit();
            Err(crate::error::GitdError::Busy(format!(
                "{} pack RPCs are already running; retry in {RETRY_AFTER_SECS}s",
                busy.limit
            )))
        }
    }
}

/// Run `rpc` under `gate` and emit its record. `bytes_out` reads the response
/// size from `rpc`'s result. `rpc` must not touch a client socket.
pub(crate) fn admitted<T>(
    gate: &'static PackRpcGate,
    service: PackService,
    repo: &str,
    bytes_in: u64,
    bytes_out: impl FnOnce(&T) -> u64,
    rpc: impl FnOnce() -> crate::error::Result<T>,
) -> crate::error::Result<T> {
    let admission = admit(gate, service, repo, bytes_in)?;
    let result = rpc();
    admission.finish(result.as_ref().ok().map(bytes_out));
    result
}

/// A writer that counts what passes through it, for a streamed response.
#[derive(Debug)]
pub(crate) struct CountingWriter<W> {
    inner: W,
    count: u64,
}

impl<W> CountingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self { inner, count: 0 }
    }

    pub(crate) fn count(&self) -> u64 {
        self.count
    }
}

impl<W: std::io::Write> std::io::Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.count += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn gate_admits_up_to_its_limit_and_frees_on_drop() {
        let gate = PackRpcGate::new(2, Duration::from_millis(20));
        let first = gate.acquire().expect("first slot");
        let second = gate.acquire().expect("second slot");
        assert_eq!(second.running, 2);
        let busy = gate.acquire().expect_err("a third request must be refused");
        assert_eq!(busy.limit, 2);
        assert!(busy.waited >= Duration::from_millis(20));
        drop(first);
        let third = gate.acquire().expect("a freed slot is reused");
        assert_eq!(third.running, 2);
        drop((second, third));
    }

    #[test]
    fn a_waiting_request_takes_the_slot_another_frees() {
        let gate = Arc::new(PackRpcGate::new(1, Duration::from_secs(5)));
        let held = gate.acquire().expect("slot");
        let waiter = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || gate.acquire().map(|permit| permit.waited))
        };
        std::thread::sleep(Duration::from_millis(50));
        drop(held);
        let waited = waiter
            .join()
            .expect("waiter")
            .expect("admitted after the release");
        assert!(waited >= Duration::from_millis(40), "waited {waited:?}");
    }

    #[test]
    fn never_more_than_the_limit_run_at_once() {
        let gate = Arc::new(PackRpcGate::new(3, Duration::from_secs(10)));
        let now = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..12)
            .map(|_| {
                let (gate, now, peak) = (Arc::clone(&gate), Arc::clone(&now), Arc::clone(&peak));
                std::thread::spawn(move || {
                    let _permit = gate.acquire().expect("admitted within the wait");
                    let current = now.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(10));
                    now.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker");
        }
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn an_oversized_wait_is_clamped_instead_of_overflowing() {
        let gate = PackRpcGate::new(1, Duration::from_secs(u64::MAX));
        assert_eq!(gate.wait, MAX_WAIT);
        let held = gate.acquire().expect("slot");
        drop(held);
    }

    #[test]
    fn a_streamed_rpc_is_recorded_without_holding_a_slot() {
        let gate: &'static PackRpcGate =
            Box::leak(Box::new(PackRpcGate::new(1, Duration::from_millis(10))));
        let streamed = record_streamed(gate, PackService::UploadPack, "acme/widgets", 10);
        let buffered = admit(gate, PackService::UploadPack, "acme/widgets", 10)
            .expect("a streamed RPC must not occupy the only slot");
        streamed.finish(Some(1));
        buffered.finish(Some(1));
    }

    #[test]
    fn a_record_is_one_json_line_with_every_field() {
        let record = PackRpcRecord {
            service: "git-upload-pack",
            repo: "acme/widgets".to_string(),
            bytes_in: 120,
            bytes_out: 4096,
            wait: Duration::from_millis(3),
            duration: Duration::from_millis(250),
            running: 2,
            limit: 8,
            outcome: "ok",
        };
        let json = record.to_json();
        assert_eq!(json["event"], "gitd.pack_rpc");
        assert_eq!(json["service"], "git-upload-pack");
        assert_eq!(json["repo"], "acme/widgets");
        assert_eq!(json["bytes_in"], 120);
        assert_eq!(json["bytes_out"], 4096);
        assert_eq!(json["wait_ms"], 3);
        assert_eq!(json["duration_ms"], 250);
        assert_eq!(json["running"], 2);
        assert_eq!(json["limit"], 8);
        assert_eq!(json["outcome"], "ok");
        assert!(!json.to_string().contains('\n'));
    }
}
