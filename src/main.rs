use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use configparser::ini::Ini;
use monitord::report::{self, ReportListener, ReportServer};
use tokio::signal::unix::{signal, Signal, SignalKind};
use tokio::sync::RwLock;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

const REPORT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const LONG_ABOUT: &str = "monitord: Know how happy your systemd is! 😊";
/// Clap CLI Args struct with metadata in help output
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = LONG_ABOUT)]
struct Cli {
    /// Location of your monitord config
    #[clap(
        short,
        long,
        value_parser,
        env = "MONITORD_CONFIG",
        default_value = "/etc/monitord.conf"
    )]
    config: PathBuf,

    /// Adjust the console log-level
    #[arg(long, short, value_enum, ignore_case = true, default_value = "Info")]
    log_level: monitord::logging::LogLevels,
}

fn main() -> anyhow::Result<()> {
    // monitord re-executes itself as a tiny helper inside each machine's PID
    // namespace (see monitord::varlink::machine_connector). Dispatch that
    // before clap and before starting a multi-threaded runtime it never needs.
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some(monitord::varlink::machine_connector::HELPER_ARG) {
        monitord::varlink::machine_connector::helper_main(&argv[2..]);
    }
    // SAFETY: no runtime or other threads exist, and nothing else owns fd 3.
    let activation_fd = unsafe { report::take_activation_fd() }?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async_main(activation_fd));
    // Blocking collectors must not keep a stopped daemon alive indefinitely.
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    result
}

async fn async_main(activation_fd: Option<OwnedFd>) -> anyhow::Result<()> {
    let args = Cli::parse();
    monitord::logging::setup_logging(args.log_level.into());

    info!("{}", LONG_ABOUT);
    debug!("CLI Args: {:?}", args);
    debug!("Loading {:?} config", args.config.as_os_str());
    let mut config = Ini::new();
    let _config_map = config
        .load(args.config)
        .map_err(|e| anyhow::anyhow!("Config error: {:?}", e))?;

    let config: monitord::config::Config = config.try_into()?;
    let serving = config.monitord.daemon && config.report.enabled;
    anyhow::ensure!(
        activation_fd.is_none() || serving,
        "socket activation requires [monitord] daemon=true and [report] enabled=true"
    );
    if config.report.enabled && !config.monitord.daemon {
        warn!("The monitord binary serves reports only with [monitord] daemon=true");
    }
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let stats = Arc::new(RwLock::new(monitord::MonitordStats::default()));
    let mut server = if serving {
        let listener = match activation_fd {
            Some(fd) => ReportListener::Prebound(fd),
            None => ReportListener::SelfBind(report::REPORT_DIR.into()),
        };
        let start = ReportServer::start(listener, stats.clone());
        tokio::pin!(start);
        Some(tokio::select! {
            result = &mut start => result?,
            () = stopping(&mut terminate, &mut interrupt) => {
                // Keep startup alive until it can hand over its server for
                // cleanup. Both steps share the shutdown deadline.
                let deadline = tokio::time::Instant::now() + REPORT_SHUTDOWN_TIMEOUT;
                let server = tokio::time::timeout_at(deadline, &mut start).await??;
                tokio::time::timeout_at(deadline, server.shutdown()).await??;
                return Ok(());
            }
        })
    } else {
        None
    };
    let result = {
        let collection = monitord::stat_collector(config, Some(stats), true, None);
        tokio::pin!(collection);
        tokio::select! {
            result = &mut collection => result.map(|_| ()).map_err(anyhow::Error::from),
            () = stopping(&mut terminate, &mut interrupt) => Ok(()),
            error = async {
                match server.as_mut() {
                    Some(server) => server.wait().await,
                    None => std::future::pending().await,
                }
            } => {
                error!("Report server stopped: {error:#}");
                Err(error)
            }
        }
    };
    if let Some(server) = server {
        tokio::time::timeout(REPORT_SHUTDOWN_TIMEOUT, server.shutdown()).await??;
    }
    result
}

async fn stopping(terminate: &mut Signal, interrupt: &mut Signal) {
    tokio::select! {
        _ = terminate.recv() => {},
        _ = interrupt.recv() => {},
    }
}
