// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Run a subprocess under a hard wall-clock cap and collect its stdout.
//!
//! Shared by every analyzer that shells out (package managers, `lxc-attach`,
//! `trivy`, `dpkg-query`, `systemctl`). It used to be copy-pasted into each
//! analyzer, and every copy read stdout only AFTER `try_wait` reported an
//! exit. Once a child writes more than the pipe buffer (64 KiB on Linux) its
//! `write()` blocks, so it never exits, and the poll loop kills it at the
//! timeout. Any command with big output (trivy JSON, `dpkg-query -W`, a long
//! `apt-get -s upgrade`) silently failed every tick.
//!
//! This helper `poll(2)`s stdout and stderr and drains both while it waits,
//! so output size never affects whether the child can exit. It runs on one
//! thread, with no reader threads that could outlive a timeout.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Upper bound on collected stdout. The largest legitimate producer is trivy
/// JSON for a big image (single-digit MB in practice); anything past this is
/// treated as a failure rather than letting one runaway child balloon memory.
const MAX_STDOUT_BYTES: usize = 64 * 1024 * 1024;
/// Only the tail of stderr is kept — enough for a diagnostic, never a log dump.
const STDERR_TAIL_BYTES: usize = 4096;
/// After the child exits, how long to keep draining for EOF. A grandchild
/// that inherited the pipe (e.g. something `lxc-attach` left behind) can hold
/// it open indefinitely; the child's own output is already in the pipe.
const POST_EXIT_DRAIN: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum CappedError {
    Spawn(std::io::Error),
    Io(std::io::Error),
    Timeout { after: Duration, stderr: String },
    Exit { code: Option<i32>, stderr: String },
    OutputTooLarge,
}

impl std::fmt::Display for CappedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn tail(f: &mut std::fmt::Formatter<'_>, stderr: &str) -> std::fmt::Result {
            if stderr.is_empty() { Ok(()) } else { write!(f, ": {stderr}") }
        }
        match self {
            CappedError::Spawn(e) => write!(f, "could not start: {e}"),
            CappedError::Io(e) => write!(f, "I/O error reading output: {e}"),
            CappedError::Timeout { after, stderr } => {
                write!(f, "timed out after {}s", after.as_secs())?;
                tail(f, stderr)
            }
            CappedError::Exit { code: Some(c), stderr } => {
                write!(f, "exited with code {c}")?;
                tail(f, stderr)
            }
            CappedError::Exit { code: None, stderr } => {
                write!(f, "killed by a signal")?;
                tail(f, stderr)
            }
            CappedError::OutputTooLarge => {
                write!(f, "output exceeded {} MiB", MAX_STDOUT_BYTES / (1024 * 1024))
            }
        }
    }
}

/// Stop a timed-out child gracefully: SIGTERM first so a well-behaved tool
/// (notably `apt-get update`, which traps it to clean up partial downloads and
/// release its lock) can exit cleanly, then escalate to SIGKILL only if it
/// ignores the term within a short grace window. A bare SIGKILL of `apt-get
/// update` can strand partial list files. Harmless for read-only commands,
/// which have nothing to clean up.
pub fn terminate_child(child: &mut Child) {
    let pid = child.id() as libc::pid_t;
    // SAFETY: signalling a child process we spawned and have not yet reaped.
    unsafe { libc::kill(pid, libc::SIGTERM); }
    let grace = Instant::now() + Duration::from_secs(3);
    while Instant::now() < grace {
        match child.try_wait() {
            Ok(Some(_)) => return,  // exited (and reaped) after SIGTERM
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    let _ = child.kill();   // SIGKILL fallback
    let _ = child.wait();
}

/// Keep the last `STDERR_TAIL_BYTES` of stderr, reduced to its last few
/// non-empty lines so a log message stays on one line.
fn stderr_summary(tail: &[u8]) -> String {
    let text = String::from_utf8_lossy(tail);
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let start = lines.len().saturating_sub(3);
    lines[start..].join(" | ")
}

/// Run `prog args…`, wait at most `timeout`, and return stdout when the exit
/// code is in `ok_codes`. stdin is /dev/null, so nothing can wait on input.
pub fn run(
    prog: &str, args: &[&str], timeout: Duration, ok_codes: &[i32],
) -> Result<String, CappedError> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(CappedError::Spawn)?;
    let started = Instant::now();
    let deadline = started + timeout;

    // Option so EOF can retire a stream: a closed fd is dropped and no longer
    // polled.
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut out: Vec<u8> = Vec::new();
    let mut err_tail: Vec<u8> = Vec::new();
    let mut exit: Option<std::process::ExitStatus> = None;
    let mut drain_until = deadline;
    let mut chunk = [0u8; 65536];

    loop {
        if exit.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit = Some(status);
                    drain_until = deadline.min(Instant::now() + POST_EXIT_DRAIN);
                }
                Ok(None) => {}
                Err(e) => {
                    terminate_child(&mut child);
                    return Err(CappedError::Io(e));
                }
            }
        }
        if stdout.is_none() && stderr.is_none() && exit.is_some() { break; }

        let now = Instant::now();
        if now >= drain_until {
            if exit.is_some() { break; }  // exited; an inherited fd is still open
            terminate_child(&mut child);
            return Err(CappedError::Timeout { after: timeout, stderr: stderr_summary(&err_tail) });
        }

        let mut fds: Vec<libc::pollfd> = Vec::with_capacity(2);
        if let Some(s) = &stdout {
            fds.push(libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        if let Some(s) = &stderr {
            fds.push(libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        if fds.is_empty() {
            // Both pipes closed but the child hasn't been reaped yet.
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        // Wake at least every 100 ms to re-check exit and the deadline.
        let wait_ms = (drain_until - now).as_millis().clamp(1, 100) as libc::c_int;
        // SAFETY: `fds` is a valid, exclusively borrowed slice of pollfd whose
        // fds are owned by `stdout`/`stderr`, which outlive this call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, wait_ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted { continue; }
            terminate_child(&mut child);
            return Err(CappedError::Io(e));
        }
        if rc == 0 { continue; }

        let ready = |fd: libc::c_int| fds.iter().any(|p| {
            p.fd == fd && p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        });
        // poll reported the fd readable (or hung up), so one read() returns
        // without blocking: data, or 0 at EOF.
        if let Some(s) = stdout.as_mut().filter(|s| ready(s.as_raw_fd())) {
            match s.read(&mut chunk) {
                Ok(0) => stdout = None,
                Ok(n) => {
                    if out.len() + n > MAX_STDOUT_BYTES {
                        terminate_child(&mut child);
                        return Err(CappedError::OutputTooLarge);
                    }
                    out.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    terminate_child(&mut child);
                    return Err(CappedError::Io(e));
                }
            }
        }
        if let Some(s) = stderr.as_mut().filter(|s| ready(s.as_raw_fd())) {
            match s.read(&mut chunk) {
                Ok(0) => stderr = None,
                Ok(n) => {
                    err_tail.extend_from_slice(&chunk[..n]);
                    if err_tail.len() > STDERR_TAIL_BYTES {
                        err_tail.drain(..err_tail.len() - STDERR_TAIL_BYTES);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                // stderr is diagnostic only; losing it must not fail the run.
                Err(_) => stderr = None,
            }
        }
    }

    let status = exit.expect("loop only breaks after the child exited");
    match status.code() {
        Some(c) if ok_codes.contains(&c) => Ok(String::from_utf8_lossy(&out).into_owned()),
        code => Err(CappedError::Exit { code, stderr: stderr_summary(&err_tail) }),
    }
}

/// `run` accepting only exit 0, collapsed to `Option` for callers that treat
/// every failure the same way (skip this tick, try again next one).
pub fn run_ok(prog: &str, args: &[&str], timeout: Duration) -> Option<String> {
    run(prog, args, timeout, &[0]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression: output larger than the 64 KiB pipe buffer must not
    /// deadlock the child into a timeout.
    #[test]
    fn drains_output_larger_than_pipe_buffer() {
        let out = run("sh", &["-c", "head -c 3000000 /dev/zero | tr '\\0' x"],
                      Duration::from_secs(10), &[0]).expect("large output must succeed");
        assert_eq!(out.len(), 3_000_000);
    }

    #[test]
    fn large_stderr_does_not_deadlock_either() {
        let out = run("sh", &["-c", "head -c 1000000 /dev/zero >&2; echo done"],
                      Duration::from_secs(10), &[0]).expect("must succeed");
        assert_eq!(out, "done\n");
    }

    #[test]
    fn non_zero_exit_reports_code_and_stderr_tail() {
        let e = run("sh", &["-c", "echo first >&2; echo 'bad flag --scanners' >&2; exit 3"],
                    Duration::from_secs(10), &[0]).unwrap_err();
        match &e {
            CappedError::Exit { code: Some(3), stderr } => {
                assert_eq!(stderr, "first | bad flag --scanners");
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(e.to_string(), "exited with code 3: first | bad flag --scanners");
    }

    #[test]
    fn accepted_codes_return_stdout() {
        let out = run("sh", &["-c", "echo pending; exit 100"],
                      Duration::from_secs(10), &[0, 100]).expect("100 is accepted");
        assert_eq!(out, "pending\n");
    }

    #[test]
    fn timeout_kills_the_child() {
        let started = Instant::now();
        let e = run("sleep", &["30"], Duration::from_millis(300), &[0]).unwrap_err();
        assert!(matches!(e, CappedError::Timeout { .. }), "got {e:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// A grandchild that keeps the inherited stdout open must not turn a
    /// finished command into a timeout.
    #[test]
    fn exited_child_with_lingering_grandchild_returns_output() {
        let started = Instant::now();
        let out = run("sh", &["-c", "echo ok; sleep 30 &"],
                      Duration::from_secs(20), &[0]).expect("child exited 0");
        assert_eq!(out, "ok\n");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn missing_binary_is_a_spawn_error() {
        let e = run("/nonexistent/wolfstack-test-bin", &[], Duration::from_secs(1), &[0]).unwrap_err();
        assert!(matches!(e, CappedError::Spawn(_)));
    }
}
