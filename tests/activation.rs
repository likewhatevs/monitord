//! Run with `harness = false`: environment mutation must precede all threads.
//!
//! Each case runs in a fresh, single-threaded copy of this executable.
//! The parent changes only `Command`'s environment, never its own environment.

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::fs::File;
    use std::net::TcpListener;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    const VARIABLES: [&str; 4] = [
        "LISTEN_PID",
        "LISTEN_PIDFDID",
        "LISTEN_FDS",
        "LISTEN_FDNAMES",
    ];
    const CASES: &[&str] = &[
        "listener",
        "no-pid",
        "other-pid",
        "bad-pid",
        "non-unicode-pid",
        "missing-count",
        "bad-count",
        "non-unicode-count",
        "negative-count",
        "zero-count",
        "multiple-fds",
        "closed-fd",
        "regular-file",
        "non-unix",
        "non-listening",
        "datagram",
    ];

    fn socket(kind: libc::c_int) -> OwnedFd {
        let fd = unsafe { libc::socket(libc::AF_UNIX, kind | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
        // SAFETY: socket returned a fresh descriptor, owned only here.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn child(case: &str) {
        // Give every subprocess a deadline, including a regression which hangs
        // inside activation. No runtime or background thread has been started.
        unsafe {
            libc::signal(libc::SIGALRM, libc::SIG_DFL);
            libc::alarm(10);
        }
        match case {
            "no-pid" | "other-pid" | "bad-pid" | "non-unicode-pid" => {}
            _ => {
                // SAFETY: this harness has one thread; this is child setup.
                unsafe { std::env::set_var("LISTEN_PID", std::process::id().to_string()) };
            }
        }

        // SAFETY: a new executable starts single-threaded, and no Rust object
        // in this process owns fd 3. The parent installed it before exec.
        let result = unsafe { monitord::report::take_activation_fd() };

        for name in VARIABLES {
            assert!(std::env::var_os(name).is_none(), "{case}: {name} remained");
        }
        // An unrelated variable must survive clearing activation metadata.
        assert_eq!(
            std::env::var("MONITORD_ACTIVATION_TEST_MARKER").as_deref(),
            Ok("preserve-me")
        );

        match case {
            "listener" => {
                let fd = result.expect("valid activation").expect("one listener");
                assert_eq!(fd.as_raw_fd(), 3);
                // SAFETY: fcntl reads flags on the live owned descriptor.
                let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
                assert_ne!(flags, -1);
                assert_ne!(flags & libc::FD_CLOEXEC, 0);
                drop(fd);
                assert_eq!(unsafe { libc::fcntl(3, libc::F_GETFD) }, -1);
            }
            "no-pid" | "other-pid" => {
                assert!(result.expect("activation for another process").is_none());
                // A descriptor never accepted for this process remains owned
                // by its original caller, including its original exec flags.
                assert_eq!(unsafe { libc::fcntl(3, libc::F_GETFD) }, 0);
            }
            "closed-fd" => {
                assert!(result.is_err(), "{case}: {result:?}");
                assert_eq!(unsafe { libc::fcntl(3, libc::F_GETFD) }, -1);
            }
            _ => {
                assert!(result.is_err(), "{case}: {result:?}");
                // Validation must precede ownership transfer and setting
                // CLOEXEC, so invalid input leaves its descriptor untouched.
                assert_eq!(unsafe { libc::fcntl(3, libc::F_GETFD) }, 0);
            }
        }
    }

    pub fn run() {
        let args: Vec<_> = std::env::args().collect();
        if let [_, mode, case] = args.as_slice() {
            assert_eq!(mode, "--activation-child");
            child(case);
            return;
        }

        let executable = std::env::current_exe().unwrap();
        for &case in CASES {
            let dir = tempfile::tempdir().unwrap();
            // Keep an open descriptor even for closed-fd, so Command's exec
            // error pipe cannot occupy fd 3 before the pre_exec closure.
            let fd: OwnedFd = match case {
                "regular-file" | "closed-fd" => File::open("/dev/null").unwrap().into(),
                "non-unix" => TcpListener::bind("[::1]:0").unwrap().into(),
                "non-listening" => socket(libc::SOCK_STREAM),
                "datagram" => socket(libc::SOCK_DGRAM),
                _ => UnixListener::bind(dir.path().join("activation.sock"))
                    .unwrap()
                    .into(),
            };
            let raw_fd = fd.as_raw_fd();
            let mut command = Command::new(&executable);
            command
                .args(["--activation-child", case])
                .env("LISTEN_PID", "set-to-child-pid")
                .env("LISTEN_FDS", "1")
                .env("LISTEN_FDNAMES", "io.monitord")
                .env("LISTEN_PIDFDID", "ignored-but-cleared")
                .env("MONITORD_ACTIVATION_TEST_MARKER", "preserve-me");
            match case {
                "no-pid" => {
                    command.env_remove("LISTEN_PID").env("LISTEN_FDS", "bad");
                }
                "other-pid" => {
                    command
                        .env("LISTEN_PID", std::process::id().to_string())
                        .env("LISTEN_FDS", "bad");
                }
                "bad-pid" => {
                    command.env("LISTEN_PID", "not-a-pid");
                }
                "non-unicode-pid" => {
                    command.env("LISTEN_PID", OsString::from_vec(vec![0xff]));
                }
                "missing-count" => {
                    command.env_remove("LISTEN_FDS");
                }
                "bad-count" => {
                    command.env("LISTEN_FDS", "not-a-count");
                }
                "non-unicode-count" => {
                    command.env("LISTEN_FDS", OsString::from_vec(vec![0xff]));
                }
                "negative-count" => {
                    command.env("LISTEN_FDS", "-1");
                }
                "zero-count" => {
                    command.env("LISTEN_FDS", "0");
                }
                "multiple-fds" => {
                    command.env("LISTEN_FDS", "2");
                }
                _ => {}
            }

            // SAFETY: this closure uses only async-signal-safe descriptor
            // operations between fork and exec. The captured source remains
            // open in the parent until the child has finished.
            unsafe {
                command.pre_exec(move || {
                    if raw_fd != 3 && libc::dup2(raw_fd, 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if case == "closed-fd" {
                        if libc::close(3) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    } else if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{case}: {}\nstdout: {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            println!("activation {case}: ok");
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
}
