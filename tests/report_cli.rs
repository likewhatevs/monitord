//! Check reporting policy at the library and binary entry points.

#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;

use configparser::ini::Ini;
use monitord::config::Config;

#[test]
fn test_one_shot_report_warning_only_from_binary() {
    let warning = "The monitord binary serves reports only with [monitord] daemon=true";
    let dir = tempfile::tempdir().unwrap();
    for enabled in [true, false] {
        let config_path = dir.path().join("monitord.conf");
        std::fs::write(
            &config_path,
            format!(
                r###"
[monitord]
daemon = false
output_format = json
dbus_address = unix:path={}/missing-bus

[networkd]
enabled = false

[pid1]
enabled = false

[system-state]
enabled = false

[timers]
enabled = false

[units]
enabled = false
state_stats = false
state_stats_time_in_state = false

[machines]
enabled = false

[dbus]
enabled = false
user_stats = false
peer_stats = false
peer_well_known_names_only = false
cgroup_stats = false

[boot]
enabled = false

[verify]
enabled = false

[varlink]
enabled = false

[report]
enabled = {enabled}
"###,
                dir.path().display()
            ),
        )
        .unwrap();
        let mut ini = Ini::new();
        ini.load(&config_path).unwrap();
        let log = tempfile::NamedTempFile::new().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .without_time()
            .with_writer(Arc::new(log.reopen().unwrap()))
            .finish();
        let config: Config = tracing::subscriber::with_default(subscriber, || ini.try_into())
            .expect("valid one-shot report configuration");
        assert!(!config.monitord.daemon);
        assert_eq!(config.report.enabled, enabled);
        let messages = std::fs::read_to_string(log.path()).unwrap();
        assert!(messages.is_empty(), "library parser warned: {messages}");

        let mut command = Command::new(env!("CARGO_BIN_EXE_monitord"));
        command.args(["--config", config_path.to_str().unwrap()]);
        for name in [
            "LISTEN_PID",
            "LISTEN_PIDFDID",
            "LISTEN_FDS",
            "LISTEN_FDNAMES",
        ] {
            command.env_remove(name);
        }
        // SAFETY: only async-signal-safe calls run between fork and exec.
        // The alarm bounds a regression that hangs instead of collecting once.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGALRM, libc::SIG_DFL);
                libc::alarm(10);
                Ok(())
            });
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{}: {stderr}", output.status);
        assert_eq!(stderr.matches(warning).count(), usize::from(enabled));
        let sample: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(sample.is_object(), "binary did not collect a sample");
    }
}
