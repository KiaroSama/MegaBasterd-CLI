use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use process_wrap::std::{ChildWrapper, CommandWrap};

use crate::error::{Error, Result};
use crate::transfers::control::Control;

#[derive(Debug)]
pub struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

struct OwnedChild(Box<dyn ChildWrapper>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
        let _ = self.0.wait();
    }
}

fn capture(
    mut pipe: impl Read + Send + 'static,
    limit: usize,
    sender: mpsc::Sender<()>,
    failed: Arc<AtomicBool>,
) -> JoinHandle<Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let result = (|| {
            let mut output = Vec::new();
            let mut block = [0u8; 8192];
            loop {
                let read = pipe.read(&mut block)?;
                if read == 0 {
                    return Ok(output);
                }
                if read > limit.saturating_sub(output.len()) {
                    return Err(Error::protocol(
                        "External process output exceeded its size limit",
                    ));
                }
                output.extend_from_slice(&block[..read]);
            }
        })();
        if result.is_err() {
            failed.store(true, Ordering::Release);
        }
        let _ = sender.send(());
        result
    })
}

pub fn run(
    executable: &Path,
    args: &[OsString],
    timeout: Duration,
    max_stdout: usize,
    max_stderr: usize,
    control: &Control,
) -> Result<ProcessOutput> {
    let mut command = Command::new(executable);
    command.args(args);
    run_command(command, timeout, max_stdout, max_stderr, control, None)
}

pub fn run_with_input(
    executable: &Path,
    args: &[OsString],
    timeout: Duration,
    max_stdout: usize,
    max_stderr: usize,
    control: &Control,
    input: File,
) -> Result<ProcessOutput> {
    if !input.metadata()?.is_file() {
        return Err(Error::invalid("External media input is not a regular file"));
    }
    let mut command = Command::new(executable);
    command.args(args);
    run_command(
        command,
        timeout,
        max_stdout,
        max_stderr,
        control,
        Some(input),
    )
}

/// Capture a prepared command with the same cancellation, limits and owned-tree cleanup.
/// The caller may isolate its environment/CWD; stdin is always explicit and never inherited.
pub fn run_command(
    mut command: Command,
    timeout: Duration,
    max_stdout: usize,
    max_stderr: usize,
    control: &Control,
    input: Option<File>,
) -> Result<ProcessOutput> {
    control.checkpoint()?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error::invalid("Process time limit overflows"))?;
    if timeout.is_zero() {
        return Err(Error::Timeout);
    }
    if let Some(file) = &input
        && !file.metadata()?.is_file()
    {
        return Err(Error::invalid(
            "External process input is not a regular file",
        ));
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.stdin(input.map_or_else(Stdio::null, Stdio::from));
    let mut command = CommandWrap::from(command);
    #[cfg(unix)]
    command.wrap(process_wrap::std::ProcessGroup::leader());
    #[cfg(windows)]
    {
        use windows::Win32::System::Threading::CREATE_NO_WINDOW;
        command.wrap(process_wrap::std::CreationFlags(CREATE_NO_WINDOW));
        command.wrap(process_wrap::std::JobObject);
    }
    let mut child = OwnedChild(command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::MissingTool("Requested external executable".into())
        } else {
            error.into()
        }
    })?);
    let stdout = child
        .0
        .stdout()
        .take()
        .ok_or_else(|| Error::protocol("External process stdout pipe is unavailable"))?;
    let stderr = child
        .0
        .stderr()
        .take()
        .ok_or_else(|| Error::protocol("External process stderr pipe is unavailable"))?;
    let (sender, receiver) = mpsc::channel();
    let failed = Arc::new(AtomicBool::new(false));
    let stdout = capture(stdout, max_stdout, sender.clone(), failed.clone());
    let stderr = capture(stderr, max_stderr, sender, failed.clone());
    let mut status = None;
    let mut failure = None;
    loop {
        if control.is_canceled() {
            failure = Some(Error::Canceled);
            break;
        }
        if Instant::now() >= deadline {
            failure = Some(Error::Timeout);
            break;
        }
        // process-wrap 10's Windows JobObject::try_wait consumes completion
        // packets without caching the job status. Preserve those packets for
        // the final wrapped wait, or cleanup can wait forever after child exit.
        #[cfg(windows)]
        let polled = child.0.inner_mut().try_wait();
        #[cfg(not(windows))]
        let polled = child.0.try_wait();
        match polled {
            Ok(Some(exited)) => status = Some(exited),
            Ok(None) => (),
            Err(error) => {
                failure = Some(error.into());
                break;
            }
        }
        if failed.load(Ordering::Acquire) {
            failure = Some(Error::protocol(
                "External process output capture failed or exceeded its limit",
            ));
            break;
        }
        if stdout.is_finished() && stderr.is_finished() && status.is_some() {
            break;
        }
        match receiver.recv_timeout(
            Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
        ) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Err(error) = control.wait(
                    Duration::from_millis(25)
                        .min(deadline.saturating_duration_since(Instant::now())),
                ) {
                    failure = Some(error);
                    break;
                }
            }
        }
    }
    // Also terminate descendants that kept running after their parent closed its pipes.
    // The wrapper targets only this process's owned group/job and reaps it before return.
    let kill = child.0.start_kill();
    let reaped = child.0.wait();
    let stdout_result = stdout.join();
    let stderr_result = stderr.join();
    let stdout =
        stdout_result.map_err(|_| Error::protocol("External stdout reader was interrupted"))?;
    let stderr =
        stderr_result.map_err(|_| Error::protocol("External stderr reader was interrupted"))?;
    if let Some(error) = failure {
        if reaped.is_err() {
            kill?;
            reaped?;
        }
        return Err(error);
    }
    let status =
        status.ok_or_else(|| Error::protocol("External process returned no exit status"))?;
    reaped?;
    Ok(ProcessOutput {
        status,
        stdout: stdout?,
        stderr: stderr?,
    })
}
