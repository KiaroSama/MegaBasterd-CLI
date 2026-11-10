#![allow(clippy::unwrap_used)]

use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use super::*;

fn pair() -> (File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: both outputs are writable; null optional name/mode/size accepts native defaults.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0,
        "could not create an isolated PTY: {}",
        io::Error::last_os_error()
    );
    // SAFETY: successful openpty transferred these two distinct descriptors exactly once.
    let pair = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    for file in [&pair.0, &pair.1] {
        // SAFETY: the owned descriptor stays live; fcntl changes only this test-owned description.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        if file.as_raw_fd() == pair.0.as_raw_fd() {
            assert_eq!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    pair
}

fn mode(file: &File) -> libc::termios {
    let mut value = std::mem::MaybeUninit::uninit();
    // SAFETY: one live terminal and writable termios output; read only after success.
    assert_eq!(
        unsafe { libc::tcgetattr(file.as_raw_fd(), value.as_mut_ptr()) },
        0
    );
    unsafe { value.assume_init() }
}

fn same_mode(expected: &libc::termios, actual: &libc::termios) {
    assert_eq!(expected.c_iflag, actual.c_iflag);
    assert_eq!(expected.c_oflag, actual.c_oflag);
    assert_eq!(expected.c_cflag, actual.c_cflag);
    assert_eq!(expected.c_lflag, actual.c_lflag);
    assert_eq!(expected.c_cc, actual.c_cc);
    // SAFETY: both termios values were initialized by tcgetattr.
    assert_eq!(unsafe { libc::cfgetispeed(expected) }, unsafe {
        libc::cfgetispeed(actual)
    });
    assert_eq!(unsafe { libc::cfgetospeed(expected) }, unsafe {
        libc::cfgetospeed(actual)
    });
}

fn line(reader: &mut Reader<'_>, control: &Control, secret: bool) -> String {
    let answer =
        super::super::read_line(control, secret, &AtomicBool::new(false), || reader.next())
            .unwrap()
            .unwrap();
    answer.to_string()
}

fn write_input(
    master: &mut File,
    mut remaining: &[u8],
    control: &Control,
    drain_echo: bool,
) -> io::Result<()> {
    let until = Instant::now() + Duration::from_secs(3);
    while !remaining.is_empty() {
        if control.is_canceled() || Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PTY writer expired",
            ));
        }
        if drain_echo {
            let mut echo = [0; 1024];
            match master.read(&mut echo) {
                Ok(_) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        match master.write(&remaining[..remaining.len().min(512)]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => remaining = &remaining[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let mut descriptor = libc::pollfd {
                    fd: master.as_raw_fd(),
                    events: libc::POLLOUT | if drain_echo { libc::POLLIN } else { 0 },
                    revents: 0,
                };
                // SAFETY: one initialized pollfd, owned master remains live until return.
                if unsafe { libc::poll(&mut descriptor, 1, 50) } < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct Deadline {
    cancel: Control,
    stop: mpsc::SyncSender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
    expired: Arc<AtomicBool>,
}

impl Deadline {
    fn new(control: &Control) -> Self {
        let cancel = control.clone();
        let (stop, stopped) = mpsc::sync_channel(1);
        let expired = Arc::new(AtomicBool::new(false));
        let timeout = expired.clone();
        let worker = std::thread::spawn(move || {
            if matches!(
                stopped.recv_timeout(Duration::from_secs(5)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                timeout.store(true, Ordering::Release);
                cancel.cancel();
            }
        });
        Self {
            cancel: control.clone(),
            stop,
            worker: Some(worker),
            expired,
        }
    }

    fn finish(mut self) {
        let _ = self.stop.try_send(());
        self.worker.take().unwrap().join().unwrap();
        assert!(
            !self.expired.load(Ordering::Acquire),
            "PTY fixture exceeded its five-second ceiling"
        );
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = self.stop.try_send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn actual_private_pty_preserves_cooked_input_hidden_echo_eof_and_original_mode() {
    let (mut master, slave) = pair();
    let original = mode(&slave);
    // SAFETY: slave is owned and live for the entire test.
    let original_flags = unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(original_flags & libc::O_NONBLOCK, 0);
    for secret in [false, true] {
        let control = Control::new();
        let deadline = Deadline::new(&control);
        let mut reader = Reader::new(&slave, secret, &control).unwrap();
        let current = mode(&slave);
        assert_eq!(current.c_lflag & libc::ICANON == 0, secret);
        assert_ne!(current.c_lflag & libc::ISIG, 0);
        assert_eq!(current.c_lflag & libc::ECHO == 0, secret);
        assert_eq!(
            current.c_iflag & (libc::ICRNL | libc::INLCR | libc::IGNCR),
            0
        );
        if secret {
            assert_eq!(current.c_cc[libc::VMIN], 1);
            assert_eq!(current.c_cc[libc::VTIME], 0);
        } else {
            assert_eq!(current.c_cc[libc::VEOL], b'\r');
            assert_eq!(current.c_lflag & libc::ECHOCTL, 0);
        }
        master
            .write_all("نام  file 🙂\nsecond\n".as_bytes())
            .unwrap();
        assert_eq!(line(&mut reader, &control, secret), "نام  file 🙂");
        reader.finish().unwrap();
        drop(reader);
        same_mode(&original, &mode(&slave));
        let mut next = Reader::new(&slave, secret, &control).unwrap();
        assert_eq!(line(&mut next, &control, secret), "second");
        next.finish().unwrap();
        drop(next);
        same_mode(&original, &mode(&slave));
        assert_eq!(
            unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) },
            original_flags
        );
        // Drain visible echo before the hidden case; never let a prior visible line prove a leak.
        let mut echo = Vec::new();
        let mut block = [0; 256];
        loop {
            match master.read(&mut block) {
                Ok(0) => break,
                Ok(count) => {
                    echo.extend_from_slice(&block[..count]);
                    assert!(echo.len() <= 4096);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("PTY echo read failed: {error}"),
            }
        }
        assert_eq!(echo.is_empty(), secret);
        deadline.finish();
    }
    let control = Control::new();
    let deadline = Deadline::new(&control);
    for secret in [false, true] {
        let mut reader = Reader::new(&slave, secret, &control).unwrap();
        master.write_all(&[original.c_cc[libc::VEOF]]).unwrap();
        assert!(
            super::super::read_line(&control, secret, &AtomicBool::new(false), || reader.next())
                .unwrap()
                .is_none()
        );
        drop(reader);
        same_mode(&original, &mode(&slave));
    }
    let mut reader = Reader::new(&slave, true, &control).unwrap();
    master.write_all(&[0xff, b'\n']).unwrap();
    assert!(matches!(
        super::super::read_line(&control, true, &AtomicBool::new(false), || reader.next()),
        Err(Error::Invalid(message)) if message == "Prompt input is not UTF-8"
    ));
    drop(reader);
    same_mode(&original, &mode(&slave));
    let outcome = std::panic::catch_unwind(|| {
        let _reader = Reader::new(&slave, true, &control).unwrap();
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(outcome.is_err());
    same_mode(&original, &mode(&slave));
    deadline.finish();
}

#[test]
fn actual_hidden_pty_preserves_long_secrets_and_refuses_application_overflow() {
    use super::super::super::prompts::MAX_PROMPT_BYTES;

    let limit = "é".repeat(MAX_PROMPT_BYTES / 2);
    for overflow in [false, true] {
        let (mut master, slave) = pair();
        let original = mode(&slave);
        let control = Control::new();
        let deadline = Deadline::new(&control);
        let mut reader = Reader::new(&slave, true, &control).unwrap();
        let input = format!("{limit}{}\r\nnext\n", if overflow { "x" } else { "" });
        let pending_lf = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let control = &control;
            let master = &mut master;
            let input = &input;
            let writer = scope.spawn(move || write_input(master, input.as_bytes(), control, false));
            let result = super::super::read_line(control, true, &pending_lf, || reader.next());
            if overflow {
                assert!(
                    matches!(result, Err(Error::Invalid(message)) if message == "Secret prompt input exceeds 64 KiB")
                );
            } else {
                assert_eq!(result.unwrap().unwrap().as_str(), limit);
                let next = super::super::read_line(control, true, &pending_lf, || reader.next())
                    .unwrap()
                    .unwrap();
                assert_eq!(next.as_str(), "next");
            }
            writer.join().unwrap().unwrap();
        });
        reader.finish().unwrap();
        drop(reader);
        same_mode(&original, &mode(&slave));
        let mut echo = [0; 16];
        assert!(
            matches!(master.read(&mut echo), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        deadline.finish();
    }
}

#[test]
fn actual_pty_keeps_crlf_and_blank_enter_distinct_across_mode_restoration() {
    for separator in [b"\r".as_slice(), b"\r\n", b"\n"] {
        for secret in [false, true] {
            let (mut master, slave) = pair();
            let original = mode(&slave);
            let control = Control::new();
            let deadline = Deadline::new(&control);
            let pending_lf = AtomicBool::new(false);
            let mut first = Reader::new(&slave, true, &control).unwrap();
            master.write_all(b"secret").unwrap();
            master.write_all(separator).unwrap();
            let answer = super::super::read_line(&control, true, &pending_lf, || first.next())
                .unwrap()
                .unwrap();
            assert_eq!(answer.as_str(), "secret");
            first.finish().unwrap();
            drop(first);
            same_mode(&original, &mode(&slave));
            for input in [b"\r".as_slice(), b"next\r\n"] {
                let mut next = Reader::new(&slave, secret, &control).unwrap();
                master.write_all(input).unwrap();
                let answer = super::super::read_line(&control, secret, &pending_lf, || next.next())
                    .unwrap()
                    .unwrap();
                assert_eq!(answer.as_str(), if input.len() == 1 { "" } else { "next" });
                next.finish().unwrap();
                drop(next);
                same_mode(&original, &mode(&slave));
            }
            deadline.finish();
        }
    }
}

#[test]
fn actual_cooked_pty_refuses_capacity_reaching_answers_instead_of_accepting_truncated_input() {
    let (mut master, slave) = pair();
    let original = mode(&slave);
    let control = Control::new();
    let deadline = Deadline::new(&control);
    let mut reader = Reader::new(&slave, false, &control).unwrap();
    let limit = reader.visible_limit.unwrap();
    assert!(limit > 1 && limit <= super::super::MAX_PROMPT_BYTES);
    let accepted = "x".repeat(limit.min(128) - 1);
    master.write_all(accepted.as_bytes()).unwrap();
    master.write_all(b"\n").unwrap();
    assert_eq!(line(&mut reader, &control, false), accepted);
    reader.finish().unwrap();
    drop(reader);
    same_mode(&original, &mode(&slave));

    let mut reader = Reader::new(&slave, false, &control).unwrap();
    let input = format!("{}\n", "x".repeat(limit));
    std::thread::scope(|scope| {
        let control = &control;
        let master = &mut master;
        let input = &input;
        let writer = scope.spawn(move || write_input(master, input.as_bytes(), control, true));
        assert!(matches!(
            super::super::read_line(control, false, &AtomicBool::new(false), || reader.next()),
            Err(Error::Invalid(message)) if message == "Prompt input reaches the terminal's safe line limit; use CLI arguments for long values"
        ));
        writer.join().unwrap().unwrap();
    });
    drop(reader);
    same_mode(&original, &mode(&slave));
    deadline.finish();
}

#[test]
fn actual_empty_pty_read_returns_canceled_without_an_input_byte() {
    let (_master, slave) = pair();
    let original = mode(&slave);
    let control = Control::new();
    let deadline = Deadline::new(&control);
    let (ready, receiving) = mpsc::sync_channel(1);
    let (finished, result) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let slave = &slave;
        let control = &control;
        let worker = scope.spawn(move || {
            let mut reader = Reader::new(slave, true, control).unwrap();
            ready.send(()).unwrap();
            let outcome = reader.next();
            reader.finish().unwrap();
            finished.send(outcome).unwrap();
        });
        receiving.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
        let started = Instant::now();
        control.cancel();
        assert!(matches!(
            result.recv_timeout(Duration::from_secs(2)).unwrap(),
            Err(Error::Canceled)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    });
    same_mode(&original, &mode(&slave));
    deadline.finish();
}
