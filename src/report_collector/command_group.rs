//! Signal the original Linux process group even if another reaper consumes
//! the command before its descendants finish writing stdout.

use std::ffi::CString;
use std::io::{self, PipeReader, PipeWriter, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Stdio;

use tokio::process::{Child, Command};

pub(super) struct CommandGroup {
    reader: PipeReader,
    writer: PipeWriter,
    kill_on_drop: bool,
}

impl CommandGroup {
    pub(super) fn spawn(path: &Path) -> io::Result<(Child, Self)> {
        let executable = CString::new(path.as_os_str().as_bytes())?;
        let (mut reader, writer) = io::pipe()?;
        // The child's stdio is installed before pre_exec runs.
        if reader.as_raw_fd() < 3 {
            reader = reader.try_clone()?;
        }
        let fd = reader.as_raw_fd();
        // F_SETSIG from <asm/fcntl.h>. libc does not expose it on Linux.
        const F_SETSIG: libc::c_int = 10;
        if unsafe { libc::fcntl(fd, F_SETSIG, libc::SIGKILL) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let mut command = Command::new(path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        // SAFETY: the hook uses only async-signal-safe operations. Both pipe
        // descriptors are close-on-exec and the executable was prepared above.
        unsafe {
            command.pre_exec(move || {
                // setpgid has already made this live child the group leader.
                // F_SETOWN stores a kernel reference to the group on the shared
                // open file description. No later lookup by numeric PID is needed.
                if libc::fcntl(fd, libc::F_SETOWN, -libc::getpid()) == -1 {
                    return Err(io::Error::last_os_error());
                }
                // execvp can invoke /bin/sh on ENOEXEC. Run only the named file.
                libc::execv(
                    executable.as_ptr(),
                    [executable.as_ptr(), std::ptr::null()].as_ptr(),
                );
                Err(io::Error::last_os_error())
            });
        }
        let child = command.spawn()?;
        Ok((
            child,
            Self {
                reader,
                writer,
                kill_on_drop: true,
            },
        ))
    }

    pub(super) fn disarm(mut self) {
        self.kill_on_drop = false;
    }

    pub(super) fn kill(mut self) -> io::Result<()> {
        self.kill_on_drop = false;
        self.signal()
    }

    fn signal(&mut self) -> io::Result<()> {
        // A write to an async pipe delivers its configured signal to its owner.
        // Arm it only here: dropping an unarmed pipe on a wait error is silent.
        if unsafe { libc::fcntl(self.reader.as_raw_fd(), libc::F_SETFL, libc::O_ASYNC) } == -1 {
            return Err(io::Error::last_os_error());
        }
        self.writer.write_all(&[1])
    }
}

impl Drop for CommandGroup {
    fn drop(&mut self) {
        // Runtime shutdown can drop the command task before its deadline.
        if self.kill_on_drop {
            if let Err(err) = self.signal() {
                tracing::warn!("Unable to signal cancelled report command group: {err}");
            }
        }
    }
}
