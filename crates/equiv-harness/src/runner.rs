//! Execute a generated probe and turn its output into a safe verdict.
//!
//! The generated binary deliberately has a tiny `EQUIV_PROBE_V1` protocol: one
//! JSON object on stdout and an exit code of `0` (no divergence) or `1`
//! (divergence found).
//! This module is the trust boundary around that protocol. It treats build
//! failures, timeouts, malformed output, and replay mismatches as `UNKNOWN`.
//! It never promotes a failed or merely sampled run to `EQUIVALENT`.

use std::fmt;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use equiv_core::{Impact, Reason, Verdict, Witness};
use serde::Deserialize;

const PROTOCOL_VERSION: u32 = 1;
const PROTOCOL_PREFIX: &str = "EQUIV_PROBE_V1 ";
const MAX_CAPTURED_OUTPUT: usize = 1024 * 1024;

/// Limits for one generated probe decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub iterations: u64,
    pub seed: u64,
    pub width: usize,
    pub timeout: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            iterations: 200_000,
            seed: 0,
            width: 64,
            timeout: Duration::from_secs(120),
        }
    }
}

impl RunOptions {
    fn validate(&self) -> Result<(), Reason> {
        if self.iterations == 0 {
            return Err(Reason::InvalidRunOptions(
                "iterations must be greater than zero".into(),
            ));
        }
        if self.width == 0 {
            return Err(Reason::InvalidRunOptions(
                "width must be greater than zero".into(),
            ));
        }
        if self.timeout.is_zero() {
            return Err(Reason::InvalidRunOptions(
                "timeout must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    diverges: bool,
    function: Option<String>,
    domain: Option<String>,
    input: Option<String>,
    old: Option<String>,
    new: Option<String>,
    witness_hex: Option<String>,
    samples: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireObservation {
    protocol: u32,
    diverges: bool,
    #[serde(rename = "fn")]
    function: Option<String>,
    domain: Option<String>,
    input: Option<String>,
    old: Option<String>,
    new: Option<String>,
    witness_hex: Option<String>,
    samples: Option<u64>,
    replayed: Option<bool>,
}

#[derive(Debug)]
enum RunError {
    Spawn(std::io::Error),
    TimedOut {
        stage: &'static str,
        timeout: Duration,
    },
    Process {
        stage: &'static str,
        status: ExitStatus,
        stderr: String,
    },
    Output {
        stage: &'static str,
        detail: String,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "could not start cargo: {e}"),
            Self::TimedOut { stage, timeout } => {
                write!(f, "{stage} exceeded {} seconds", timeout.as_secs())
            }
            Self::Process {
                stage,
                status,
                stderr,
            } => {
                write!(f, "{stage} exited with {status}")?;
                if !stderr.trim().is_empty() {
                    write!(f, ": {}", compact(stderr))?;
                }
                Ok(())
            }
            Self::Output { stage, detail } => write!(f, "{stage} output is invalid: {detail}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Run a generated probe, replaying any finding before returning `DIVERGES`.
///
/// `old_ref` and `new_ref` are caller-supplied immutable artifact identifiers
/// (for example crate versions plus checksums). They are recorded in the
/// witness only after the replay matches the original observation.
pub fn decide(
    probe_dir: &Path,
    options: &RunOptions,
    old_ref: impl Into<String>,
    new_ref: impl Into<String>,
) -> Verdict {
    decide_impl(probe_dir, options, old_ref.into(), new_ref.into(), None)
}

/// Run a probe while checking that path-backed artifacts did not change during
/// the find-and-replay sequence.
///
/// This is the preferred API for local or vendored sources. Path sources are
/// content-hashed; a mutation turns the result into `UNKNOWN` instead of
/// attaching a witness to the wrong artifact. Registry sources are identified
/// by exact package version and are additionally integrity-checked by Cargo.
pub fn decide_checked(
    probe: &crate::ProbeCrate,
    probe_dir: &Path,
    options: &RunOptions,
) -> Verdict {
    let old_ref = match probe.old.fingerprint(&probe.package) {
        Ok(value) => value,
        Err(error) => return Verdict::unknown(Reason::BuildFailed(error.to_string())),
    };
    let new_ref = match probe.new.fingerprint(&probe.package) {
        Ok(value) => value,
        Err(error) => return Verdict::unknown(Reason::BuildFailed(error.to_string())),
    };
    let guard = ArtifactGuard {
        package: &probe.package,
        old: &probe.old,
        new: &probe.new,
        old_ref: old_ref.clone(),
        new_ref: new_ref.clone(),
    };
    decide_impl(probe_dir, options, old_ref, new_ref, Some(&guard))
}

struct ArtifactGuard<'a> {
    package: &'a str,
    old: &'a crate::project::Source,
    new: &'a crate::project::Source,
    old_ref: String,
    new_ref: String,
}

impl ArtifactGuard<'_> {
    fn unchanged(&self) -> Result<(), Reason> {
        let old = self
            .old
            .fingerprint(self.package)
            .map_err(|error| Reason::ArtifactChanged {
                side: "old".into(),
                detail: error.to_string(),
            })?;
        if old != self.old_ref {
            return Err(Reason::ArtifactChanged {
                side: "old".into(),
                detail: "content fingerprint changed during the probe".into(),
            });
        }
        let new = self
            .new
            .fingerprint(self.package)
            .map_err(|error| Reason::ArtifactChanged {
                side: "new".into(),
                detail: error.to_string(),
            })?;
        if new != self.new_ref {
            return Err(Reason::ArtifactChanged {
                side: "new".into(),
                detail: "content fingerprint changed during the probe".into(),
            });
        }
        Ok(())
    }
}

fn decide_impl(
    probe_dir: &Path,
    options: &RunOptions,
    old_ref: String,
    new_ref: String,
    guard: Option<&ArtifactGuard<'_>>,
) -> Verdict {
    if let Err(reason) = options.validate() {
        return Verdict::unknown(reason);
    }

    let found = match find(probe_dir, options) {
        Ok(observation) => observation,
        Err(error) => return Verdict::unknown(error.reason()),
    };

    if let Some(guard) = guard {
        if let Err(reason) = guard.unchanged() {
            return Verdict::unknown(reason);
        }
    }

    if !found.diverges {
        return Verdict::unknown(Reason::NoDivergenceFound {
            samples: found.samples.unwrap_or(options.iterations),
        });
    }

    let Some(hex) = found.witness_hex.as_deref() else {
        return Verdict::unknown(Reason::ProbeOutputInvalid {
            stage: "find".into(),
            detail: "diverges=true without witness_hex".into(),
        });
    };

    let replay = match replay(probe_dir, options, hex) {
        Ok(observation) => observation,
        Err(error) => return Verdict::unknown(error.reason()),
    };

    if let Some(guard) = guard {
        if let Err(reason) = guard.unchanged() {
            return Verdict::unknown(reason);
        }
    }

    if !replay.diverges
        || replay.function != found.function
        || replay.domain != found.domain
        || replay.input != found.input
        || replay.old != found.old
        || replay.new != found.new
        || replay.witness_hex.as_deref() != Some(hex)
    {
        return Verdict::unknown(Reason::ReplayMismatch {
            detail: "replay did not reproduce the original finding exactly".into(),
        });
    }

    let (Some(input), Some(old), Some(new)) = (replay.input, replay.old, replay.new) else {
        return Verdict::unknown(Reason::ProbeOutputInvalid {
            stage: "replay".into(),
            detail: "diverges=true without input, old, or new observation".into(),
        });
    };
    let witness = Witness::candidate(input, old, new).confirm(old_ref, new_ref);
    Verdict::diverges(vec![witness], Some(Impact::from_witnesses(1, None)))
        .expect("replay-confirmed witness must produce DIVERGES")
}

fn find(probe_dir: &Path, options: &RunOptions) -> Result<Observation, RunError> {
    let args = vec![
        "--iters".to_string(),
        options.iterations.to_string(),
        "--seed".to_string(),
        options.seed.to_string(),
        "--width".to_string(),
        options.width.to_string(),
    ];
    run_stage(probe_dir, "find", &args, options.timeout)
}

fn replay(probe_dir: &Path, options: &RunOptions, hex: &str) -> Result<Observation, RunError> {
    run_stage(
        probe_dir,
        "replay",
        &["--replay".into(), hex.into()],
        options.timeout,
    )
}

fn run_stage(
    probe_dir: &Path,
    stage: &'static str,
    args: &[String],
    timeout: Duration,
) -> Result<Observation, RunError> {
    let manifest = probe_dir.join("Cargo.toml");
    if !manifest.is_file() {
        return Err(RunError::Output {
            stage,
            detail: format!("missing generated manifest {}", manifest.display()),
        });
    }

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    configure_process_group(&mut command);
    command
        .args(["run", "--quiet", "--manifest-path"])
        .arg(&manifest)
        .arg("--")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = command.spawn().map_err(RunError::Spawn)?;
    let output = wait_with_timeout(child, timeout, stage)?;
    if output.stdout_truncated || output.stderr_truncated {
        return Err(RunError::Output {
            stage,
            detail: format!(
                "captured output exceeded the {} byte safety limit",
                MAX_CAPTURED_OUTPUT
            ),
        });
    }
    let code = output.status.code();
    if !matches!(code, Some(0) | Some(1)) {
        return Err(RunError::Process {
            stage,
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(PROTOCOL_PREFIX))
        .ok_or_else(|| RunError::Output {
            stage,
            detail: format!("no `{PROTOCOL_PREFIX}` record on stdout"),
        })?;
    let wire: WireObservation = serde_json::from_str(line).map_err(|e| RunError::Output {
        stage,
        detail: e.to_string(),
    })?;

    if wire.protocol != PROTOCOL_VERSION {
        return Err(RunError::Output {
            stage,
            detail: format!("unsupported protocol version {}", wire.protocol),
        });
    }
    let expected_code = if wire.diverges { Some(1) } else { Some(0) };
    if code != expected_code {
        return Err(RunError::Output {
            stage,
            detail: format!(
                "exit code {code:?} disagrees with diverges={}",
                wire.diverges
            ),
        });
    }

    if wire.diverges
        && (wire.function.is_none()
            || wire.domain.is_none()
            || wire.input.is_none()
            || wire.old.is_none()
            || wire.new.is_none()
            || wire
                .witness_hex
                .as_deref()
                .is_none_or(|hex| !valid_hex(hex)))
    {
        return Err(RunError::Output {
            stage,
            detail: "diverges=true without complete observations".into(),
        });
    }
    if !wire.diverges
        && stage == "find"
        && (wire.samples.is_none() || wire.function.is_none() || wire.domain.is_none())
    {
        return Err(RunError::Output {
            stage,
            detail: "find result is missing samples or function".into(),
        });
    }
    if !wire.diverges && stage == "replay" && wire.replayed != Some(true) {
        return Err(RunError::Output {
            stage,
            detail: "replay result is missing replayed=true".into(),
        });
    }

    Ok(Observation {
        diverges: wire.diverges,
        function: wire.function,
        domain: wire.domain,
        input: wire.input,
        old: wire.old,
        new: wire.new,
        witness_hex: wire.witness_hex,
        samples: wire.samples,
    })
}

struct StageOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

fn wait_with_timeout(
    mut child: Child,
    timeout: Duration,
    stage: &'static str,
) -> Result<StageOutput, RunError> {
    let stdout = child.stdout.take().ok_or_else(|| RunError::Output {
        stage,
        detail: "stdout was not piped".into(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| RunError::Output {
        stage,
        detail: "stderr was not piped".into(),
    })?;
    let stdout_reader = thread::spawn(|| read_capped(stdout));
    let stderr_reader = thread::spawn(|| read_capped(stderr));
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(RunError::Spawn)? {
            // Cargo normally waits for every child it starts. Closing the
            // process group before joining readers also handles a build script
            // that orphaned a descendant while keeping a pipe open.
            terminate_child(&mut child);
            let stdout = join_capture(stdout_reader, stage, "stdout")?;
            let stderr = join_capture(stderr_reader, stage, "stderr")?;
            return Ok(StageOutput {
                status,
                stdout: stdout.bytes,
                stderr: stderr.bytes,
                stdout_truncated: stdout.truncated,
                stderr_truncated: stderr.truncated,
            });
        }
        if Instant::now() >= deadline {
            terminate_child(&mut child);
            let _ = child.wait();
            #[cfg(unix)]
            {
                let _ = join_capture(stdout_reader, stage, "stdout");
                let _ = join_capture(stderr_reader, stage, "stderr");
            }
            #[cfg(not(unix))]
            {
                drop(stdout_reader);
                drop(stderr_reader);
            }
            return Err(RunError::TimedOut { stage, timeout });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn read_capped(mut input: impl Read) -> std::io::Result<Captured> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let n = input.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if bytes.len() < MAX_CAPTURED_OUTPUT {
            let keep = (MAX_CAPTURED_OUTPUT - bytes.len()).min(n);
            bytes.extend_from_slice(&chunk[..keep]);
            truncated |= keep < n;
        } else {
            truncated = true;
        }
    }
    Ok(Captured { bytes, truncated })
}

fn join_capture(
    handle: JoinHandle<std::io::Result<Captured>>,
    stage: &'static str,
    stream: &'static str,
) -> Result<Captured, RunError> {
    handle
        .join()
        .map_err(|_| RunError::Output {
            stage,
            detail: format!("{stream} reader panicked"),
        })?
        .map_err(|error| RunError::Output {
            stage,
            detail: format!("could not read {stream}: {error}"),
        })
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_child(child: &mut Child) {
    let process_group = -(child.id() as libc::pid_t);
    // `configure_process_group` puts cargo and its descendants in this group.
    // Fall back to the direct child kill if the group signal is rejected.
    let killed_group = unsafe { libc::kill(process_group, libc::SIGKILL) } == 0;
    if !killed_group {
        let _ = child.kill();
    }
}

#[cfg(not(unix))]
fn terminate_child(child: &mut Child) {
    let _ = child.kill();
}

fn valid_hex(hex: &str) -> bool {
    !hex.is_empty()
        && hex.len().is_multiple_of(2)
        && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl RunError {
    fn reason(&self) -> Reason {
        match self {
            Self::TimedOut { timeout, .. } => Reason::Timeout {
                seconds: timeout.as_secs(),
            },
            Self::Output { stage, detail } => Reason::ProbeOutputInvalid {
                stage: (*stage).into(),
                detail: detail.clone(),
            },
            Self::Spawn(error) => Reason::BuildFailed(error.to_string()),
            Self::Process { stage, stderr, .. } => {
                Reason::BuildFailed(format!("{stage}: {}", compact(stderr)))
            }
        }
    }
}

fn compact(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .take(4)
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_budget_is_explicit() {
        let options = RunOptions::default();
        assert_eq!(options.iterations, 200_000);
        assert_eq!(options.width, 64);
        assert_eq!(options.timeout, Duration::from_secs(120));
    }

    #[test]
    fn missing_probe_stays_unknown() {
        let verdict = decide(
            Path::new("/definitely/not/a/generated/probe"),
            &RunOptions::default(),
            "old",
            "new",
        );
        assert!(matches!(
            verdict,
            Verdict::Unknown {
                reason: Reason::ProbeOutputInvalid { .. }
            }
        ));
    }

    #[test]
    fn invalid_options_are_unknown_before_spawning() {
        let verdict = decide(
            Path::new("/unused"),
            &RunOptions {
                iterations: 0,
                ..RunOptions::default()
            },
            "old",
            "new",
        );
        assert!(matches!(
            verdict,
            Verdict::Unknown {
                reason: Reason::InvalidRunOptions(_)
            }
        ));
    }

    #[test]
    fn artifact_guard_detects_content_mutation() {
        let root =
            std::env::temp_dir().join(format!("equiv-runner-fingerprint-{}", std::process::id()));
        let old = root.join("old");
        let new = root.join("new");
        std::fs::create_dir_all(old.join("src")).unwrap();
        std::fs::create_dir_all(new.join("src")).unwrap();
        let manifest = "[package]\nname = \"x\"\nversion = \"1.0.0\"\nedition = \"2021\"\n";
        std::fs::write(old.join("Cargo.toml"), manifest).unwrap();
        std::fs::write(new.join("Cargo.toml"), manifest).unwrap();
        std::fs::write(old.join("src/lib.rs"), "pub fn f() -> u8 { 1 }\n").unwrap();
        std::fs::write(new.join("src/lib.rs"), "pub fn f() -> u8 { 1 }\n").unwrap();
        let old_source = crate::project::Source::old_path(&old);
        let new_source = crate::project::Source::new_path(&new);
        let guard = ArtifactGuard {
            package: "x",
            old: &old_source,
            new: &new_source,
            old_ref: old_source.fingerprint("x").unwrap(),
            new_ref: new_source.fingerprint("x").unwrap(),
        };
        std::fs::write(old.join("src/lib.rs"), "pub fn f() -> u8 { 2 }\n").unwrap();
        assert!(matches!(
            guard.unchanged(),
            Err(Reason::ArtifactChanged { side, .. }) if side == "old"
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
