//! # report module
//!
//! Serve monitord's own health as an `io.systemd.Metrics` source so
//! `systemd-report` (systemd ≥ 260) includes monitord in its report.
//!
//! `systemd-report` calls `io.systemd.Metrics.List` / `Describe` on every
//! socket in `/run/systemd/report/`. A source's socket must be named as a
//! varlink interface name, and every metric it returns must be prefixed with
//! that name followed by a dot. Metrics without the prefix are dropped as
//! invalid. So the socket is always [`REPORT_SOCKET_NAME`] and every family
//! in [`FAMILIES`] starts with it.
//!
//! These metrics cover monitord itself: whether its last collection run
//! was clean, how long each collector took, and failure counters. They do
//! not re-export the stats monitord collects, which systemd's own report
//! sources already publish.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::stream::{self, FuturesUnordered};
use futures_util::StreamExt;
use rustix::io::{fcntl_getfd, fcntl_setfd, FdFlags};
use rustix::net::sockopt::{socket_acceptconn, socket_domain, socket_type};
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zlink::connection::socket::{ReadHalf as ZlinkReadHalf, ReadResult, UnixSocket};
use zlink::connection::Socket as ZlinkSocket;
use zlink::introspect;

use crate::{CollectorTiming, MonitordStats};

/// Socket filename, which is also the prefix of every metric name.
pub const REPORT_SOCKET_NAME: &str = "io.monitord";
/// Directory `systemd-report` scans for system-scope sources.
pub const REPORT_DIR: &str = "/run/systemd/report";
/// Maximum number of clients the report server serves at once.
const REPORT_CONNECTIONS_MAX: usize = 64;
/// Leave capacity for report clients owned by other local users.
const REPORT_CONNECTIONS_PER_UID_MAX: usize = 8;
/// Maximum size of a request frame before its NUL terminator.
const REPORT_REQUEST_MAX_BYTES: usize = 64 * 1024;

/// First fd systemd passes in socket activation (`SD_LISTEN_FDS_START`).
const SD_LISTEN_FDS_START: i32 = 3;

/// Metric family type, as in systemd's `io.systemd.Metrics` IDL.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, introspect::Type)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum MetricFamilyType {
    Counter,
    Gauge,
    String,
    /// Arbitrary JSON object. monitord exports none; listed so our
    /// introspected IDL matches systemd's.
    Object,
}

/// A metric value: any JSON value, `any` in systemd's IDL (a systemd
/// extension zlink can describe but not derive for `serde_json::Value`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct MetricValue(pub serde_json::Value);

impl introspect::Type for MetricValue {
    const TYPE: &'static zlink::idl::Type<'static> = &zlink::idl::Type::Any;
}

/// One metric family: (name suffix after `io.monitord.`, description, type).
pub const FAMILIES: &[(&str, &str, MetricFamilyType)] = &[
    (
        "collectionErrorsTotal",
        "Collection runs where at least one collector failed",
        MetricFamilyType::Counter,
    ),
    (
        "collectionRunTimeMs",
        "Wall time of the last collection run in milliseconds",
        MetricFamilyType::Gauge,
    ),
    (
        "collectionRunsTotal",
        "Collection runs completed since monitord started",
        MetricFamilyType::Counter,
    ),
    (
        "collectorElapsedMs",
        "Wall time of each collector in the last run in milliseconds",
        MetricFamilyType::Gauge,
    ),
    (
        "collectorFailuresTotal",
        "Failed runs of each collector since monitord started",
        MetricFamilyType::Counter,
    ),
    (
        "collectorSuccess",
        "1 if the collector succeeded in the last run, else 0",
        MetricFamilyType::Gauge,
    ),
    (
        "healthy",
        "1 if the last collection run had no collector failures, else 0",
        MetricFamilyType::Gauge,
    ),
    (
        "lastCollectionTimestamp",
        "Unix time in seconds when the last collection run finished",
        MetricFamilyType::Gauge,
    ),
    (
        "varlinkUsage",
        "1 if varlink served the collector in the last run, 0 for D-Bus",
        MetricFamilyType::Gauge,
    ),
    ("version", "monitord version", MetricFamilyType::String),
];

/// Counters kept across collection runs, skipped in stats JSON output.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ReportState {
    pub collection_runs_total: u64,
    pub collection_errors_total: u64,
    /// Failure count per collector name. Every collector seen gets an
    /// entry, so a counter is present at 0 before its first failure.
    pub collector_failures_total: BTreeMap<String, u64>,
    /// `None` until the first run finishes.
    pub last_collection_timestamp: Option<u64>,
    pub last_run_healthy: bool,
}

impl ReportState {
    /// Record a finished collection run.
    pub fn record_run(&mut self, timings: &[CollectorTiming], had_error: bool) {
        self.collection_runs_total += 1;
        if had_error {
            self.collection_errors_total += 1;
        }
        for timing in timings {
            let failures = self
                .collector_failures_total
                .entry(timing.name.clone())
                .or_default();
            if !timing.success {
                *failures += 1;
            }
        }
        self.last_run_healthy = !had_error;
        self.last_collection_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
    }
}

/// `io.systemd.Metrics.List` reply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, introspect::Type)]
pub struct MetricReply {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    pub value: MetricValue,
}

/// `io.systemd.Metrics.Describe` reply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, introspect::Type)]
pub struct DescribeReply {
    pub name: String,
    pub description: String,
    pub r#type: MetricFamilyType,
}

/// Errors this source sends back, named as systemd names them.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError)]
#[zlink(interface = "org.varlink.service")]
pub enum ReportError {
    /// `List`/`Describe` called without the `more` flag.
    ExpectedMore,
}

/// `ExpectedMore` is a standard `org.varlink.service` error, so it is kept
/// out of the `io.systemd.Metrics` IDL we introspect as.
impl introspect::ReplyError for ReportError {
    const VARIANTS: &'static [&'static zlink::idl::Error<'static>] = &[];
}

fn full_name(suffix: &str) -> String {
    format!("{REPORT_SOCKET_NAME}.{suffix}")
}

fn metric(suffix: &str, object: Option<&str>, value: impl Into<serde_json::Value>) -> MetricReply {
    MetricReply {
        name: full_name(suffix),
        object: object.map(str::to_string),
        value: MetricValue(value.into()),
    }
}

/// Build replies only from fields committed together at the end of a run.
/// Do not read mid-run fields such as `machines` or `report` here.
///
/// Before the first run there are no timings and no timestamp, so only
/// the version, the run counters and `healthy` = 0 are returned.
pub(crate) fn build_metrics(stats: &MonitordStats) -> Vec<MetricReply> {
    let state = &stats.report_state;
    let mut metrics = vec![
        metric("version", None, env!("CARGO_PKG_VERSION")),
        metric("healthy", None, u64::from(state.last_run_healthy)),
        metric("collectionRunsTotal", None, state.collection_runs_total),
        metric("collectionErrorsTotal", None, state.collection_errors_total),
    ];
    if let Some(ts) = state.last_collection_timestamp {
        metrics.push(metric("lastCollectionTimestamp", None, ts));
        metrics.push(metric(
            "collectionRunTimeMs",
            None,
            stats.stat_collection_run_time_ms,
        ));
    }
    for timing in &stats.collector_timings {
        let object = Some(timing.name.as_str());
        metrics.push(metric("collectorElapsedMs", object, timing.elapsed_ms));
        metrics.push(metric(
            "collectorSuccess",
            object,
            u64::from(timing.success),
        ));
    }
    for (name, failures) in &state.collector_failures_total {
        metrics.push(metric("collectorFailuresTotal", Some(name), *failures));
    }
    let usage = serde_json::to_value(&stats.varlink_usage).unwrap_or_default();
    if let serde_json::Value::Object(usage) = usage {
        for (collector, transport) in usage {
            if transport.is_null() {
                continue;
            }
            metrics.push(metric("varlinkUsage", Some(&collector), transport));
        }
    }
    metrics
}

/// Mark every reply but the last as continued, as a streamed reply needs.
fn into_stream<T>(
    items: Vec<T>,
) -> impl futures_util::Stream<Item = Result<zlink::Reply<T>, ReportError>> + Unpin {
    let last = items.len().saturating_sub(1);
    stream::iter(
        items
            .into_iter()
            .enumerate()
            .map(move |(i, item)| Ok(zlink::Reply::new(Some(item)).set_continues(Some(i < last)))),
    )
}

fn expected_more<T>(
) -> impl futures_util::Stream<Item = Result<zlink::Reply<T>, ReportError>> + Unpin {
    stream::iter(vec![Err(ReportError::ExpectedMore)])
}

/// The `io.systemd.Metrics` service.
struct MetricsService {
    stats: Arc<RwLock<MonitordStats>>,
}

impl MetricsService {
    fn new(stats: Arc<RwLock<MonitordStats>>) -> Self {
        Self { stats }
    }

    /// Build replies under the same lock used to commit each completed run.
    async fn snapshot(&self) -> Vec<MetricReply> {
        let stats = self.stats.read().await;
        build_metrics(&stats)
    }
}

#[zlink::service(
    interface = "io.systemd.Metrics",
    vendor = "monitord",
    product = "monitord",
    version = env!("CARGO_PKG_VERSION"),
    url = "https://github.com/cooperlees/monitord"
)]
impl MetricsService {
    #[zlink(more)]
    async fn list(
        &self,
        more: bool,
    ) -> impl futures_util::Stream<Item = Result<zlink::Reply<MetricReply>, ReportError>> + Unpin
    {
        if !more {
            return futures_util::future::Either::Left(expected_more());
        }
        let metrics = self.snapshot().await;
        futures_util::future::Either::Right(into_stream(metrics))
    }

    #[zlink(more)]
    async fn describe(
        &self,
        more: bool,
    ) -> impl futures_util::Stream<Item = Result<zlink::Reply<DescribeReply>, ReportError>> + Unpin
    {
        if !more {
            return futures_util::future::Either::Left(expected_more());
        }
        let families = FAMILIES
            .iter()
            .map(|(suffix, description, kind)| DescribeReply {
                name: full_name(suffix),
                description: description.to_string(),
                r#type: *kind,
            })
            .collect();
        futures_util::future::Either::Right(into_stream(families))
    }
}

/// Take the single listening Unix stream socket passed for this process.
///
/// Returns `None` if `LISTEN_PID` is unset or names another process. Malformed
/// or ambiguous activation is an error. All four `LISTEN_*` variables are
/// cleared on every path; accepted descriptors are marked close-on-exec.
///
/// # Safety
///
/// Call before any other thread starts: this removes environment variables.
/// Nothing else in the process may own fd 3. Call at most once.
pub unsafe fn take_activation_fd() -> anyhow::Result<Option<OwnedFd>> {
    let pid = std::env::var_os("LISTEN_PID");
    let count = std::env::var_os("LISTEN_FDS");
    for name in [
        "LISTEN_PID",
        "LISTEN_PIDFDID",
        "LISTEN_FDS",
        "LISTEN_FDNAMES",
    ] {
        // SAFETY: the caller guarantees there are no other threads.
        unsafe { std::env::remove_var(name) };
    }
    let Some(pid) = pid else {
        return Ok(None);
    };
    let pid: u32 = pid
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid LISTEN_PID"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid LISTEN_PID"))?;
    if pid != std::process::id() {
        return Ok(None);
    }
    let count: u32 = count
        .as_deref()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid LISTEN_FDS"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid LISTEN_FDS"))?;
    anyhow::ensure!(
        count == 1,
        "expected exactly one activation fd, got {count}"
    );
    // Activation metadata can name a closed fd. Check before borrowing it.
    if unsafe { libc::fcntl(SD_LISTEN_FDS_START, libc::F_GETFD) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fd 3 is open and the caller guarantees exclusive access.
    let fd = unsafe { BorrowedFd::borrow_raw(SD_LISTEN_FDS_START) };
    validate_listener(fd)?;
    set_cloexec(fd)?;
    // SAFETY: validation proved fd 3 is open; the caller guarantees sole ownership.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) }))
}

fn set_cloexec(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    Ok(fcntl_setfd(fd, fcntl_getfd(fd)? | FdFlags::CLOEXEC)?)
}

fn validate_listener(fd: BorrowedFd<'_>) -> anyhow::Result<()> {
    anyhow::ensure!(
        socket_domain(fd).map_err(std::io::Error::from)? == AddressFamily::UNIX,
        "report fd must be a listening Unix stream socket (not Unix domain)"
    );
    anyhow::ensure!(
        socket_type(fd).map_err(std::io::Error::from)? == SocketType::STREAM,
        "report fd must be a listening Unix stream socket (not stream)"
    );
    anyhow::ensure!(
        socket_acceptconn(fd).map_err(std::io::Error::from)?,
        "report fd must be a listening Unix stream socket (not listening)"
    );
    Ok(())
}

/// Probe a Unix socket without blocking when its accept queue is full.
fn probe_socket(path: &Path) -> std::io::Result<()> {
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )?;
    // Require room for the trailing NUL. rustix also accepts a full-width path.
    std::os::unix::net::SocketAddr::from_pathname(path).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid Unix socket path")
    })?;
    connect(&fd, &SocketAddrUnix::new(path)?).map_err(Into::into)
}

/// Bind `path`, replacing a socket file only if nobody is serving on it.
///
/// Only probe after `AddrInUse`. A refused connection means the socket is
/// stale; a successful connection or a full accept queue means it is live.
/// Anything that isn't a socket is left alone.
fn bind_unless_served(path: &Path) -> anyhow::Result<UnixListener> {
    let bind = || -> zlink::Result<UnixListener> {
        let listener = UnixListener::bind(path)?;
        #[cfg(target_os = "linux")]
        zlink::unix_utils::tag_listener(&listener, Some(path));
        Ok(listener)
    };
    match bind() {
        Ok(listener) => return Ok(listener),
        Err(zlink::Error::Io(e)) if e.kind() == std::io::ErrorKind::AddrInUse => {}
        Err(e) => return Err(e.into()),
    }
    let file_type = std::fs::symlink_metadata(path)?.file_type();
    if !file_type.is_socket() {
        anyhow::bail!(
            "{} exists and is not a socket; not replacing it",
            path.display()
        );
    }
    match probe_socket(path) {
        Ok(()) => anyhow::bail!(
            "{} is already being served (another monitord or monitord-report.socket)",
            path.display()
        ),
        Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => anyhow::bail!(
            "{} is already being served (its accept queue is full)",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            debug!("Replacing stale {}", path.display());
            std::fs::remove_file(path)?;
            Ok(bind()?)
        }
        Err(e) => Err(anyhow::anyhow!(
            "Unable to tell whether {} is in use: {e}",
            path.display()
        )),
    }
}

/// Where the managed report server gets its listener.
pub enum ReportListener {
    /// Bind `io.monitord` in this existing, absolute directory.
    SelfBind(PathBuf),
    /// Adopt a listening Unix stream socket, such as a socket-activation fd.
    /// The descriptor becomes close-on-exec. The socket becomes nonblocking,
    /// which also affects duplicate descriptors. Its path is left untouched.
    Prebound(OwnedFd),
}

struct SocketCleanup {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl SocketCleanup {
    fn new(path: PathBuf) -> std::io::Result<Self> {
        let metadata = std::fs::symlink_metadata(&path)?;
        Ok(Self {
            path,
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) if (metadata.dev(), metadata.ino()) == (self.dev, self.ino) => {
                if let Err(error) = std::fs::remove_file(&self.path) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        warn!("Unable to remove {}: {error}", self.path.display());
                    }
                }
            }
            Ok(_) => warn!(
                "Leaving replaced report socket {} alone",
                self.path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!(
                "Unable to inspect {} for cleanup: {error}",
                self.path.display()
            ),
        }
    }
}

/// Create the listener inside the runtime that will serve it, so it registers
/// with that runtime's reactor. Keep `cleanup` alive until the runtime closes.
fn listener(
    spec: ReportListener,
    cleanup: &mut Option<SocketCleanup>,
    #[cfg(test)] set_cloexec_override: Option<fn(BorrowedFd<'_>) -> std::io::Result<()>>,
) -> anyhow::Result<UnixListener> {
    #[cfg(test)]
    let set_cloexec = set_cloexec_override.unwrap_or(set_cloexec);
    match spec {
        ReportListener::Prebound(fd) => {
            validate_listener(fd.as_fd())?;
            set_cloexec(fd.as_fd())?;
            info!("Serving {REPORT_SOCKET_NAME} metrics on a prebound fd");
            let listener = std::os::unix::net::UnixListener::from(fd);
            listener.set_nonblocking(true).map_err(zlink::Error::Io)?;
            let listener = UnixListener::from_std(listener).map_err(zlink::Error::Io)?;
            #[cfg(target_os = "linux")]
            zlink::unix_utils::tag_listener(&listener, None);
            Ok(listener)
        }
        ReportListener::SelfBind(dir) => {
            anyhow::ensure!(dir.is_absolute(), "report directory must be absolute");
            anyhow::ensure!(
                dir.is_dir(),
                "{} does not exist; systemd-report needs systemd 260 or newer",
                dir.display()
            );
            let path = dir.join(REPORT_SOCKET_NAME);
            let listener = bind_unless_served(&path)?;
            // Record identity before chmod so setup failures also clean up.
            *cleanup = Some(SocketCleanup::new(path.clone())?);
            // Let unprivileged systemd-report read these health metrics,
            // matching systemd's metric source sockets (SocketMode=0666).
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
            info!("Serving {REPORT_SOCKET_NAME} metrics on {}", path.display());
            Ok(listener)
        }
    }
}

/// No report method accepts file descriptors. Keep each request frame small
/// and hand zlink only one complete frame at a time.
#[derive(Debug)]
struct ReportSocket(zlink::tokio::unix::Stream);

impl ZlinkSocket for ReportSocket {
    type ReadHalf = ReportReadHalf;
    type WriteHalf = <zlink::tokio::unix::Stream as ZlinkSocket>::WriteHalf;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        let (read, write) = ZlinkSocket::split(self.0);
        (
            ReportReadHalf {
                inner: read,
                queued: VecDeque::new(),
                frame_bytes: 0,
            },
            write,
        )
    }
}

#[derive(Debug)]
struct ReportReadHalf {
    inner: <zlink::tokio::unix::Stream as ZlinkSocket>::ReadHalf,
    queued: VecDeque<u8>,
    frame_bytes: usize,
}

impl ReportReadHalf {
    fn check_frame(&mut self, bytes: &[u8]) -> zlink::Result<()> {
        for byte in bytes {
            if *byte == 0 {
                self.frame_bytes = 0;
            } else {
                self.frame_bytes += 1;
                if self.frame_bytes > REPORT_REQUEST_MAX_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "report request exceeds 64 KiB",
                    )
                    .into());
                }
            }
        }
        Ok(())
    }
}

impl AsFd for ReportReadHalf {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl UnixSocket for ReportReadHalf {}

impl ZlinkReadHalf for ReportReadHalf {
    async fn read(&mut self, buf: &mut [u8]) -> zlink::Result<ReadResult> {
        if !self.queued.is_empty() {
            let mut count = 0;
            while count < buf.len() {
                let Some(byte) = self.queued.pop_front() else {
                    break;
                };
                buf[count] = byte;
                count += 1;
                if byte == 0 {
                    break;
                }
            }
            self.check_frame(&buf[..count])?;
            return Ok(ReadResult::new(count));
        }

        let mut result = ZlinkReadHalf::read(&mut self.inner, buf).await?;
        if !result.fds().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "report clients may not pass file descriptors",
            )
            .into());
        }
        let size = result.bytes_read();
        let end = buf[..size]
            .iter()
            .position(|byte| *byte == 0)
            .map_or(size, |index| index + 1);
        self.queued.extend(&buf[end..size]);
        self.check_frame(&buf[..end])?;
        #[cfg(target_os = "linux")]
        let credentials = result.take_credentials();
        let next = ReadResult::new(end);
        #[cfg(target_os = "linux")]
        let next = next.set_credentials(credentials);
        Ok(next)
    }
}

async fn serve(
    listener: UnixListener,
    stats: Arc<RwLock<MonitordStats>>,
    max_connections: usize,
    per_uid_limit: usize,
    #[cfg(test)] mut fail_accept: Option<tokio::sync::oneshot::Receiver<()>>,
    #[cfg(test)] mut accept_error_handled: Option<tokio::sync::oneshot::Sender<()>>,
) -> anyhow::Result<()> {
    let mut clients = FuturesUnordered::new();
    let mut clients_by_uid = BTreeMap::<u32, usize>::new();
    loop {
        let accept = listener.accept();
        #[cfg(test)]
        let accept = tests::inject_accept_error(accept, &mut fail_accept);
        tokio::select! {
            biased;
            Some((uid, result)) = clients.next(), if !clients.is_empty() => {
                let count = clients_by_uid.get_mut(&uid).expect("admitted uid must be counted");
                *count -= 1;
                if *count == 0 {
                    clients_by_uid.remove(&uid);
                }
                result?;
            }
            accepted = accept, if clients.len() < max_connections => {
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error)
                        if !clients.is_empty()
                            && matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) =>
                    {
                        warn!("Report socket reached its file descriptor limit; closing {} clients", clients.len());
                        clients = FuturesUnordered::new();
                        clients_by_uid.clear();
                        #[cfg(test)]
                        if let Some(handled) = accept_error_handled.take() {
                            let _ = handled.send(());
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let uid = match stream.peer_cred() {
                    Ok(credentials) => credentials.uid(),
                    Err(error) => {
                        debug!("Unable to get report client credentials: {error}");
                        continue;
                    }
                };
                if clients_by_uid.get(&uid).copied().unwrap_or(0) >= per_uid_limit {
                    debug!("Too many report clients from uid {uid}; closing new connection");
                    continue;
                }
                #[cfg(target_os = "linux")]
                zlink::unix_utils::tag_socket(&stream, zlink::unix_utils::SocketRole::Server);
                let socket = ReportSocket(stream.try_into()?);
                let service = MetricsService::new(stats.clone());
                *clients_by_uid.entry(uid).or_default() += 1;
                clients.push(async move {
                    (uid, zlink::Server::new(zlink::ReadyListener::new(socket), service).run().await)
                });
            }
        }
    }
}

#[cfg(test)]
#[derive(Default)]
struct ServerHooks {
    set_cloexec: Option<fn(BorrowedFd<'_>) -> std::io::Result<()>>,
    bound: Option<tokio::sync::oneshot::Sender<()>>,
    before_ready: Option<tokio::sync::oneshot::Receiver<()>>,
    ready_sent: Option<tokio::sync::oneshot::Sender<()>>,
    panic_before_ready: bool,
    panic_after_ready: Option<tokio::sync::oneshot::Receiver<()>>,
    failure: Option<tokio::sync::oneshot::Receiver<()>>,
    cleaned: Option<tokio::sync::oneshot::Sender<()>>,
    connection_limit: Option<usize>,
    per_uid_limit: Option<usize>,
    accept_error: Option<tokio::sync::oneshot::Receiver<()>>,
    accept_error_handled: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Own a report server running on a dedicated current-thread Tokio runtime.
///
/// Startup reports listener setup errors. Call [`Self::wait`] alongside your
/// collection loop to supervise later failure, and [`Self::shutdown`] for an
/// orderly stop. Dropping the handle requests a stop without waiting.
///
/// The dedicated runtime accommodates zlink's non-Send server future.
/// At most 64 clients, and eight per user, are served concurrently. Requests
/// over 64 KiB and passed file descriptors are rejected. File descriptor
/// exhaustion with active clients closes them and retries; other serve errors
/// reach wait.
/// Cleanup checks the bound path's device and inode before removing it. Only
/// one server should bind each path: checking identity and unlinking are
/// separate operations. SIGKILL and process crashes leave a stale socket,
/// which the next server can reclaim.
pub struct ReportServer {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    terminal: Option<tokio::sync::oneshot::Receiver<anyhow::Result<()>>>,
}

impl ReportServer {
    /// Return once the listener is registered, or after failed setup is cleaned
    /// up. Cancelling this future requests a stop, even if readiness was sent.
    pub async fn start(
        spec: ReportListener,
        stats: Arc<RwLock<MonitordStats>>,
    ) -> anyhow::Result<Self> {
        Self::start_inner(
            spec,
            stats,
            #[cfg(test)]
            ServerHooks::default(),
        )
        .await
    }

    async fn start_inner(
        spec: ReportListener,
        stats: Arc<RwLock<MonitordStats>>,
        #[cfg(test)] mut hooks: ServerHooks,
    ) -> anyhow::Result<Self> {
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let (ready, readiness) = tokio::sync::oneshot::channel();
        let (terminal, finished) = tokio::sync::oneshot::channel();
        // Own the stop sender before the first await, so cancelled startup and
        // failed thread creation also release it.
        let handle = Self {
            stop: Some(stop),
            terminal: Some(finished),
        };
        std::thread::Builder::new()
            .name("monitord-report".into())
            .spawn(move || {
                let mut cleanup = None;
                let mut ready = Some(ready);
                let run = || -> anyhow::Result<()> {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(async {
                        let listener = listener(
                            spec,
                            &mut cleanup,
                            #[cfg(test)]
                            hooks.set_cloexec,
                        )?;
                        #[cfg(test)]
                        if let Some(bound) = hooks.bound.take() {
                            let _ = bound.send(());
                        }
                        #[cfg(test)]
                        if let Some(gate) = hooks.before_ready.take() {
                            let _ = gate.await;
                        }
                        #[cfg(test)]
                        assert!(!hooks.panic_before_ready, "injected startup panic");
                        if ready.take().unwrap().send(Ok(())).is_err() {
                            return Ok(());
                        }
                        #[cfg(test)]
                        if let Some(sent) = hooks.ready_sent.take() {
                            let _ = sent.send(());
                        }
                        let serving = async {
                            #[cfg(test)]
                            {
                                tokio::select! {
                                    result = serve(
                                        listener,
                                        stats,
                                        hooks.connection_limit.unwrap_or(REPORT_CONNECTIONS_MAX),
                                        hooks.per_uid_limit.unwrap_or(REPORT_CONNECTIONS_PER_UID_MAX),
                                        hooks.accept_error.take(),
                                        hooks.accept_error_handled.take(),
                                    ) => result,
                                    _ = async {
                                        if let Some(failure) = hooks.failure.take() {
                                            let _ = failure.await;
                                        } else {
                                            std::future::pending::<()>().await;
                                        }
                                    } => anyhow::bail!("injected serve failure"),
                                    _ = async {
                                        if let Some(panic) = hooks.panic_after_ready.take() {
                                            let _ = panic.await;
                                        } else {
                                            std::future::pending::<()>().await;
                                        }
                                    } => panic!("injected serve panic"),
                                }
                            }
                            #[cfg(not(test))]
                            {
                                serve(
                                    listener,
                                    stats,
                                    REPORT_CONNECTIONS_MAX,
                                    REPORT_CONNECTIONS_PER_UID_MAX,
                                ).await
                            }
                        };
                        tokio::select! {
                            biased;
                            result = serving => match result {
                                Err(error) => Err(error),
                                Ok(()) => Err(anyhow::anyhow!("report server stopped unexpectedly")),
                            },
                            _ = stopping => Ok(()),
                        }
                    })
                };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
                    .unwrap_or_else(|panic| {
                        let message = panic
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("unknown panic payload");
                        Err(anyhow::anyhow!("report server thread panicked: {message}"))
                    });
                // Listeners and runtime have closed. Keeping readiness alive
                // across catch_unwind lets us clean up before reporting even
                // a startup panic.
                drop(cleanup);
                #[cfg(test)]
                if let Some(cleaned) = hooks.cleaned.take() {
                    let _ = cleaned.send(());
                }
                if let Some(ready) = ready {
                    let message = result
                        .as_ref()
                        .err()
                        .map(|e| format!("{e:#}"))
                        .unwrap_or_else(|| "report setup stopped unexpectedly".into());
                    let _ = ready.send(Err(anyhow::anyhow!(message)));
                }
                let _ = terminal.send(result);
            })?;
        readiness
            .await
            .map_err(|_| anyhow::anyhow!("report server thread stopped during startup"))??;
        Ok(handle)
    }

    /// Resolve with the cause only if serving stops unexpectedly. Cancel-safe.
    /// Once a cause is returned, subsequent calls remain pending.
    pub async fn wait(&mut self) -> anyhow::Error {
        if let Some(terminal) = self.terminal.as_mut() {
            let result = terminal.await;
            self.terminal = None;
            return match result {
                Ok(Err(error)) => error,
                Ok(Ok(())) => anyhow::anyhow!("report server stopped unexpectedly"),
                Err(_) => anyhow::anyhow!("report server thread panicked or disappeared"),
            };
        }
        std::future::pending().await
    }

    /// Stop serving and await cleanup. Return any failure not already consumed
    /// by [`Self::wait`]. Prebound sockets are only closed, never shut down.
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        self.stop.take();
        if let Some(terminal) = self.terminal.take() {
            terminal
                .await
                .map_err(|_| anyhow::anyhow!("report server thread panicked or disappeared"))??;
        }
        Ok(())
    }
}

impl Drop for ReportServer {
    fn drop(&mut self) {
        self.stop.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varlink::metrics::{Metrics, MetricsError};
    use futures_util::StreamExt;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use zlink::tokio::unix::Connection;

    pub(super) async fn inject_accept_error<T>(
        accept: impl std::future::Future<Output = std::io::Result<T>>,
        fail_accept: &mut Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> std::io::Result<T> {
        if let Some(fail) = fail_accept.as_mut() {
            tokio::select! {
                accepted = accept => return accepted,
                _ = fail => {}
            }
            *fail_accept = None;
            return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        }
        accept.await
    }

    /// Port of systemd's `varlink_idl_interface_name_is_valid`: dot
    /// separated labels of ASCII letters, digits and `-`, each starting
    /// with a letter, at least two labels.
    fn interface_name_is_valid(name: &str) -> bool {
        let labels: Vec<&str> = name.split('.').collect();
        labels.len() >= 2
            && labels.iter().all(|label| {
                label
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                    && !label.ends_with('-')
            })
    }

    /// Port of systemd's `varlink_idl_field_name_is_valid`.
    fn field_name_is_valid(name: &str) -> bool {
        name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.ends_with('_')
    }

    /// What `systemd-report` checks before it accepts a metric from the
    /// `io.monitord` source (`metrics_name_valid` + the source prefix).
    fn systemd_report_accepts(name: &str) -> bool {
        let Some((interface, field)) = name.rsplit_once('.') else {
            return false;
        };
        interface_name_is_valid(interface)
            && field_name_is_valid(field)
            && name
                .strip_prefix(REPORT_SOCKET_NAME)
                .is_some_and(|rest| rest.starts_with('.'))
    }

    fn timing(name: &str, success: bool) -> CollectorTiming {
        CollectorTiming {
            name: name.to_string(),
            start_offset_ms: 0.0,
            elapsed_ms: 1.5,
            success,
        }
    }

    #[test]
    fn test_socket_name_is_a_valid_source() {
        assert!(interface_name_is_valid(REPORT_SOCKET_NAME));
    }

    #[test]
    fn test_every_family_name_passes_systemd_report_checks() {
        for (suffix, _, _) in FAMILIES {
            assert!(systemd_report_accepts(&full_name(suffix)), "{suffix}");
        }
        assert!(!systemd_report_accepts("io.monitordfoo.bar"));
        assert!(!systemd_report_accepts("io.systemd.Manager.foo"));
    }

    #[test]
    fn test_families_are_sorted_and_unique() {
        let names: Vec<&str> = FAMILIES.iter().map(|(n, _, _)| *n).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_record_run_counts() {
        let mut state = ReportState::default();
        state.record_run(&[timing("units", true), timing("pid1", true)], false);
        assert_eq!(state.collection_runs_total, 1);
        assert_eq!(state.collection_errors_total, 0);
        assert!(state.last_run_healthy);
        assert_eq!(state.collector_failures_total["units"], 0);
        assert!(state.last_collection_timestamp.is_some());

        state.record_run(&[timing("units", false), timing("pid1", true)], true);
        assert_eq!(state.collection_runs_total, 2);
        assert_eq!(state.collection_errors_total, 1);
        assert!(!state.last_run_healthy);
        assert_eq!(state.collector_failures_total["units"], 1);
        assert_eq!(state.collector_failures_total["pid1"], 0);

        // A clean run after a failure clears healthy but keeps the counter.
        state.record_run(&[timing("units", true)], false);
        assert!(state.last_run_healthy);
        assert_eq!(state.collector_failures_total["units"], 1);
    }

    #[test]
    fn test_build_metrics_before_first_run() {
        let metrics = build_metrics(&MonitordStats::default());
        let names: Vec<&str> = metrics.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"io.monitord.version"));
        assert!(names.contains(&"io.monitord.healthy"));
        assert!(!names.contains(&"io.monitord.lastCollectionTimestamp"));
        let healthy = metrics
            .iter()
            .find(|m| m.name == "io.monitord.healthy")
            .unwrap();
        assert_eq!(healthy.value.0, serde_json::json!(0));
    }

    #[test]
    fn test_build_metrics_after_run() {
        let mut stats = MonitordStats {
            stat_collection_run_time_ms: 12.5,
            collector_timings: vec![timing("units", false)],
            ..Default::default()
        };
        stats
            .report_state
            .record_run(&stats.collector_timings, true);

        let metrics = build_metrics(&stats);
        for m in &metrics {
            assert!(systemd_report_accepts(&m.name), "{}", m.name);
        }
        let find = |name: &str, object: Option<&str>| {
            metrics
                .iter()
                .find(|m| m.name == name && m.object.as_deref() == object)
                .unwrap_or_else(|| panic!("missing {name} {object:?}"))
                .value
                .0
                .clone()
        };
        assert_eq!(find("io.monitord.healthy", None), serde_json::json!(0));
        assert_eq!(
            find("io.monitord.collectionRunTimeMs", None),
            serde_json::json!(12.5)
        );
        assert_eq!(
            find("io.monitord.collectorSuccess", Some("units")),
            serde_json::json!(0)
        );
        assert_eq!(
            find("io.monitord.collectorFailuresTotal", Some("units")),
            serde_json::json!(1)
        );
        // Disabled collectors have no transport and so no gauge.
        assert!(!metrics.iter().any(|m| m.name == "io.monitord.varlinkUsage"));
    }

    #[tokio::test]
    async fn test_snapshot_never_mixes_two_runs() {
        // A clean run is on record when a List arrives mid-collection...
        let stats = Arc::new(RwLock::new(MonitordStats {
            collector_timings: vec![timing("units", true)],
            ..Default::default()
        }));
        stats
            .write()
            .await
            .report_state
            .record_run(&[timing("units", true)], false);
        let service = MetricsService::new(stats.clone());

        // ...while the writer holds the stats lock to publish a failed run.
        let mut writer = stats.write().await;
        let mut reply = std::pin::pin!(service.snapshot());
        assert!(futures_util::poll!(reply.as_mut()).is_pending());
        writer.collector_timings = vec![timing("units", false)];
        writer
            .report_state
            .record_run(&[timing("units", false)], true);
        drop(writer);

        // The reply must describe the failed run throughout, not the old
        // run's healthy=1 next to the new run's failed collector.
        let metrics = reply.await;
        let value = |name: &str| {
            metrics
                .iter()
                .find(|m| m.name == name)
                .unwrap_or_else(|| panic!("missing {name}"))
                .value
                .0
                .clone()
        };
        assert_eq!(value("io.monitord.healthy"), serde_json::json!(0));
        assert_eq!(value("io.monitord.collectorSuccess"), serde_json::json!(0));
        assert_eq!(
            value("io.monitord.collectionErrorsTotal"),
            serde_json::json!(1)
        );
    }

    #[tokio::test]
    async fn test_self_bind_refuses_a_served_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _serving =
            bind_unless_served(&dir.path().join(REPORT_SOCKET_NAME)).expect("first listener");
        let err = bind_unless_served(&dir.path().join(REPORT_SOCKET_NAME))
            .expect_err("second listener must back off");
        assert!(err.to_string().contains("already being served"), "{err}");
        // The first listener's socket file is still there and still answers.
        std::os::unix::net::UnixStream::connect(dir.path().join(REPORT_SOCKET_NAME))
            .expect("original listener still reachable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_probe_rejects_invalid_socket_paths() {
        // A Linux pathname socket needs room for the NUL in its 108-byte sun_path.
        for path in ["x".repeat(108), "x\0y".into()] {
            let error = probe_socket(Path::new(&path)).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn test_self_bind_refuses_a_full_accept_queue_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(REPORT_SOCKET_NAME);
        let serving = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(serving.as_raw_fd(), 0) }, 0);
        let _queued = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let probe_path = path.clone();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let err = runtime.block_on(async { bind_unless_served(&probe_path).unwrap_err() });
            tx.send(err.to_string()).unwrap();
        });
        let error = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("probe blocked on a full backlog");
        assert!(error.contains("already being served"), "{error}");
        assert!(path.exists());
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn test_self_bind_reclaims_a_stale_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REPORT_SOCKET_NAME);
        crate::tests::bind_stale_socket(&path);
        assert!(path.exists());
        let _listener = bind_unless_served(&path).expect("stale socket replaced");
        std::os::unix::net::UnixStream::connect(&path).expect("new listener reachable");
    }

    #[tokio::test]
    async fn test_self_bind_leaves_non_sockets_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REPORT_SOCKET_NAME);
        std::fs::write(&path, "not a socket").expect("write");
        let err = bind_unless_served(&dir.path().join(REPORT_SOCKET_NAME))
            .expect_err("must not replace a file");
        assert!(err.to_string().contains("not a socket"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a socket");
    }

    #[tokio::test]
    async fn test_server_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let server = deadline(ReportServer::start(
            ReportListener::SelfBind(dir.path().into()),
            healthy_stats(),
        ))
        .await
        .unwrap();
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o666
        );
        deadline(round_trip_client(&socket)).await;
        deadline(server.shutdown()).await.unwrap();
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn test_report_connection_limit_keeps_server_running() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let hooks = ServerHooks {
            connection_limit: Some(2),
            ..Default::default()
        };
        let mut server = start_test_server(dir.path(), hooks).await;

        let (first, _second) = connect_two_clients(&socket).await;

        // Both served clients remain connected. A third may connect into the
        // kernel backlog, but it cannot receive a report until one leaves.
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            round_trip_client(&socket)
        )
        .await
        .is_err());
        assert_wait_pending(&mut server).await;

        drop(first);
        deadline(round_trip_client(&socket)).await;
        deadline(server.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn test_report_per_uid_connection_limit() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let hooks = ServerHooks {
            connection_limit: Some(4),
            per_uid_limit: Some(2),
            ..Default::default()
        };
        let mut server = start_test_server(dir.path(), hooks).await;

        let (first, _second) = connect_two_clients(&socket).await;

        let mut extra = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        assert_report_client_closed(&mut extra);
        drop(extra);
        drop(first);
        deadline(round_trip_client(&socket)).await;
        assert_wait_pending(&mut server).await;
        deadline(server.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn test_report_fd_limit_releases_clients_and_retries() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let (exhausted, fail_accept) = tokio::sync::oneshot::channel();
        let (accept_error_handled, handled) = tokio::sync::oneshot::channel();
        let hooks = ServerHooks {
            connection_limit: Some(2),
            per_uid_limit: Some(1),
            accept_error: Some(fail_accept),
            accept_error_handled: Some(accept_error_handled),
            ..Default::default()
        };
        let mut server = start_test_server(dir.path(), hooks).await;

        let mut held = deadline(zlink::tokio::unix::connect(&socket))
            .await
            .unwrap();
        assert_client_admitted(&mut held).await;

        // The injected accept error stands in for a low RLIMIT_NOFILE. The
        // per-user limit proves the old client was freed before a new request.
        exhausted.send(()).unwrap();
        deadline(handled).await.unwrap();
        deadline(round_trip_client(&socket)).await;
        assert_wait_pending(&mut server).await;
        deadline(server.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn test_report_rejects_passed_descriptors() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let hooks = ServerHooks {
            connection_limit: Some(1),
            ..Default::default()
        };
        let mut server = start_test_server(dir.path(), hooks).await;

        let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        zlink::unix_utils::sendmsg(&client, b" ", &[file.as_fd()], None).unwrap();
        assert_report_client_closed(&mut client);
        drop(client);

        deadline(round_trip_client(&socket)).await;
        assert_wait_pending(&mut server).await;
        deadline(server.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn test_report_rejects_oversized_requests() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let server = deadline(ReportServer::start(
            ReportListener::SelfBind(dir.path().into()),
            healthy_stats(),
        ))
        .await
        .unwrap();

        let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        client
            .write_all(&vec![b' '; REPORT_REQUEST_MAX_BYTES + 1])
            .unwrap();
        assert_report_client_closed(&mut client);
        drop(client);

        deadline(round_trip_client(&socket)).await;
        deadline(server.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn test_report_read_half_keeps_pipelined_frames() {
        let (mut sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        sender.write_all(b"a\0b\0").unwrap();
        let stream = zlink::tokio::unix::Stream::try_from(receiver).unwrap();
        let (mut read, _write) = ZlinkSocket::split(ReportSocket(stream));
        let mut buf = [0; 16];
        let first = deadline(ZlinkReadHalf::read(&mut read, &mut buf))
            .await
            .unwrap();
        assert_eq!(&buf[..first.bytes_read()], b"a\0");
        let second = deadline(ZlinkReadHalf::read(&mut read, &mut buf))
            .await
            .unwrap();
        assert_eq!(&buf[..second.bytes_read()], b"b\0");
    }

    fn assert_report_client_closed(client: &mut std::os::unix::net::UnixStream) {
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0];
        match client.read(&mut byte) {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("report client was not closed: {other:?}"),
        }
    }

    fn healthy_stats() -> Arc<RwLock<MonitordStats>> {
        let timings = vec![timing("pid1", true)];
        let mut report_state = ReportState::default();
        report_state.record_run(&timings, false);
        Arc::new(RwLock::new(MonitordStats {
            collector_timings: timings,
            report_state,
            ..Default::default()
        }))
    }

    #[tokio::test]
    async fn test_server_rejects_invalid_listeners_before_readiness() {
        let dir = tempfile::tempdir().unwrap();
        // A connected Unix stream is still not a listener. Checking only
        // domain/type would incorrectly declare this descriptor ready.
        let (connected, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let tcp = std::net::TcpListener::bind("[::1]:0").unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let invalid = [
            ReportListener::SelfBind(PathBuf::from("relative-directory")),
            ReportListener::SelfBind(dir.path().join("missing-directory")),
            ReportListener::Prebound(connected.into()),
            ReportListener::Prebound(tcp.into()),
            ReportListener::Prebound(file.into()),
        ];
        for listener in invalid {
            let (ready_sent, readiness) = tokio::sync::oneshot::channel();
            let result = deadline(ReportServer::start_inner(
                listener,
                healthy_stats(),
                ServerHooks {
                    ready_sent: Some(ready_sent),
                    ..Default::default()
                },
            ))
            .await
            .err();
            assert!(
                result.is_some(),
                "invalid listener reported successful startup"
            );
            assert!(deadline(readiness).await.is_err(), "readiness was sent");
        }
        assert!(!dir.path().join("missing-directory").exists());
    }

    #[tokio::test]
    async fn test_server_prebound_cloexec_failure_precedes_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let owner = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = std::fs::symlink_metadata(&socket).unwrap();
        let fd: OwnedFd = owner.try_clone().unwrap().into();
        let (ready_sent, readiness) = tokio::sync::oneshot::channel();
        let (cleaned, mut finished) = tokio::sync::oneshot::channel();
        let error = deadline(ReportServer::start_inner(
            ReportListener::Prebound(fd),
            healthy_stats(),
            ServerHooks {
                set_cloexec: Some(|_| Err(std::io::Error::other("injected close-on-exec failure"))),
                ready_sent: Some(ready_sent),
                cleaned: Some(cleaned),
                ..Default::default()
            },
        ))
        .await
        .err()
        .expect("close-on-exec failure must fail start");
        assert!(
            error.to_string().contains("injected close-on-exec failure"),
            "{error}"
        );
        assert!(deadline(readiness).await.is_err(), "readiness was sent");
        finished
            .try_recv()
            .expect("startup returned before cleanup");

        // Failed adoption must leave the owner's listener usable, too.
        let after = std::fs::symlink_metadata(&socket).unwrap();
        assert_eq!((after.dev(), after.ino()), (metadata.dev(), metadata.ino()));
        assert_eq!(after.permissions().mode() & 0o777, 0o600);
        owner.set_nonblocking(true).unwrap();
        let owner = tokio::net::UnixListener::from_std(owner).unwrap();
        let _client = deadline(tokio::net::UnixStream::connect(&socket))
            .await
            .unwrap();
        deadline(owner.accept()).await.unwrap();
    }

    #[tokio::test]
    async fn test_server_prebound_preserves_owners_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let owner = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let fd: OwnedFd = owner.try_clone().unwrap().into();
        let raw_fd = fd.as_raw_fd();
        // Direct embedders need the same exec protection as socket activation.
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_SETFD, 0) }, 0);
        let server = deadline(ReportServer::start(
            ReportListener::Prebound(fd),
            healthy_stats(),
        ))
        .await
        .unwrap();
        #[cfg(target_os = "linux")]
        assert_eq!(
            crate::tests::socket_fd_count(&owner),
            2,
            "one fd each for owner and server"
        );
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        deadline(round_trip_client(&socket)).await;
        deadline(server.shutdown()).await.unwrap();
        #[cfg(target_os = "linux")]
        assert_eq!(crate::tests::socket_fd_count(&owner), 1);
        assert!(socket.exists());
        // A surviving pathname alone would miss shutdown(2) on the shared
        // open file. Prove the original owner's listener can accept again.
        let owner = tokio::net::UnixListener::from_std(owner).unwrap();
        let _client = deadline(tokio::net::UnixStream::connect(&socket))
            .await
            .unwrap();
        deadline(owner.accept()).await.unwrap();
    }

    #[tokio::test]
    async fn test_server_shutdown_preserves_replaced_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let server = deadline(ReportServer::start(
            ReportListener::SelfBind(dir.path().into()),
            healthy_stats(),
        ))
        .await
        .unwrap();
        std::fs::remove_file(&socket).unwrap();
        let replacement = tokio::net::UnixListener::bind(&socket).unwrap();
        let metadata = std::fs::symlink_metadata(&socket).unwrap();
        deadline(server.shutdown()).await.unwrap();
        let after = std::fs::symlink_metadata(&socket).unwrap();
        assert_eq!((after.dev(), after.ino()), (metadata.dev(), metadata.ino()));
        let _client = deadline(tokio::net::UnixStream::connect(&socket))
            .await
            .unwrap();
        deadline(replacement.accept()).await.unwrap();
    }

    #[tokio::test]
    async fn test_server_drop_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let (cleaned, finished) = tokio::sync::oneshot::channel();
        let hooks = ServerHooks {
            cleaned: Some(cleaned),
            ..Default::default()
        };
        let server = start_test_server(dir.path(), hooks).await;
        assert!(socket.exists());
        drop(server);
        deadline(finished).await.unwrap();
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn test_server_cancel_start_before_readiness_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let (bound, binding) = tokio::sync::oneshot::channel();
        let (release, gate) = tokio::sync::oneshot::channel();
        let (cleaned, finished) = tokio::sync::oneshot::channel();
        let mut start = Box::pin(ReportServer::start_inner(
            ReportListener::SelfBind(dir.path().into()),
            healthy_stats(),
            ServerHooks {
                bound: Some(bound),
                before_ready: Some(gate),
                cleaned: Some(cleaned),
                ..Default::default()
            },
        ));
        assert!(futures_util::poll!(start.as_mut()).is_pending());
        deadline(binding).await.unwrap();
        assert!(socket.exists());
        drop(start);
        release.send(()).unwrap();
        deadline(finished).await.unwrap();
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn test_server_cancel_start_after_readiness_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let (release, gate) = tokio::sync::oneshot::channel();
        let (ready_sent, readiness) = tokio::sync::oneshot::channel();
        let (cleaned, finished) = tokio::sync::oneshot::channel();
        let mut start = Box::pin(ReportServer::start_inner(
            ReportListener::SelfBind(dir.path().into()),
            healthy_stats(),
            ServerHooks {
                before_ready: Some(gate),
                ready_sent: Some(ready_sent),
                cleaned: Some(cleaned),
                ..Default::default()
            },
        ));
        assert!(futures_util::poll!(start.as_mut()).is_pending());
        release.send(()).unwrap();
        deadline(readiness).await.unwrap();
        assert!(socket.exists());
        // Readiness is queued, but start has not been polled again to deliver
        // its handle. Cancelling here must still release the stop sender.
        drop(start);
        deadline(finished).await.unwrap();
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn test_server_startup_panic_reports_after_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let (cleaned, mut finished) = tokio::sync::oneshot::channel();
        let error = deadline(ReportServer::start_inner(
            ReportListener::SelfBind(dir.path().into()),
            healthy_stats(),
            ServerHooks {
                panic_before_ready: true,
                cleaned: Some(cleaned),
                ..Default::default()
            },
        ))
        .await
        .err()
        .expect("startup panic must fail start");
        assert!(
            error.to_string().contains("injected startup panic"),
            "{error}"
        );
        // This must already be ready when start returns its error.
        finished
            .try_recv()
            .expect("startup returned before cleanup");
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn test_server_serve_panic_reports_after_cleanup() {
        for observe_with_wait in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join(REPORT_SOCKET_NAME);
            let (panic, panicking) = tokio::sync::oneshot::channel();
            let (cleaned, mut finished) = tokio::sync::oneshot::channel();
            let hooks = ServerHooks {
                panic_after_ready: Some(panicking),
                cleaned: Some(cleaned),
                ..Default::default()
            };
            let mut server = start_test_server(dir.path(), hooks).await;
            assert!(socket.exists());
            panic.send(()).unwrap();
            let error = if observe_with_wait {
                let error = deadline(server.wait()).await;
                finished.try_recv().expect("wait returned before cleanup");
                deadline(server.shutdown())
                    .await
                    .expect("wait already returned the panic");
                error
            } else {
                // Let the panic occur before shutdown can stop the server.
                deadline(finished).await.unwrap();
                deadline(server.shutdown()).await.unwrap_err()
            };
            assert!(
                error.to_string().contains("injected serve panic"),
                "{error}"
            );
            assert!(!socket.exists());
        }
    }

    #[tokio::test]
    async fn test_server_failure_wait_is_cancel_safe_and_consumes_failure_once() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(REPORT_SOCKET_NAME);
        let (failure, fail) = tokio::sync::oneshot::channel();
        let hooks = ServerHooks {
            failure: Some(fail),
            ..Default::default()
        };
        let mut server = start_test_server(dir.path(), hooks).await;
        // Drop a pending wait, as select! does when a different arm wins.
        assert_wait_pending(&mut server).await;
        failure.send(()).unwrap();
        let error = deadline(server.wait()).await;
        assert!(
            error.to_string().contains("injected serve failure"),
            "{error}"
        );
        assert!(!socket.exists(), "wait returned before cleanup");
        assert_wait_pending(&mut server).await;
        deadline(server.shutdown())
            .await
            .expect("failure was already returned by wait");
    }

    #[tokio::test]
    async fn test_server_shutdown_returns_unobserved_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (failure, fail) = tokio::sync::oneshot::channel();
        let (cleaned, finished) = tokio::sync::oneshot::channel();
        let hooks = ServerHooks {
            failure: Some(fail),
            cleaned: Some(cleaned),
            ..Default::default()
        };
        let server = start_test_server(dir.path(), hooks).await;
        failure.send(()).unwrap();
        deadline(finished).await.unwrap();
        let error = deadline(server.shutdown()).await.unwrap_err();
        assert!(
            error.to_string().contains("injected serve failure"),
            "{error}"
        );
    }

    async fn start_test_server(dir: &Path, hooks: ServerHooks) -> ReportServer {
        deadline(ReportServer::start_inner(
            ReportListener::SelfBind(dir.into()),
            healthy_stats(),
            hooks,
        ))
        .await
        .unwrap()
    }

    async fn connect_two_clients(socket: &Path) -> (Connection, Connection) {
        let mut first = deadline(zlink::tokio::unix::connect(socket)).await.unwrap();
        let mut second = deadline(zlink::tokio::unix::connect(socket)).await.unwrap();
        for client in [&mut first, &mut second] {
            assert_client_admitted(client).await;
        }
        (first, second)
    }

    async fn assert_client_admitted(client: &mut Connection) {
        let mut replies = deadline(client.list()).await.unwrap();
        assert!(deadline(replies.next()).await.is_some());
    }

    async fn assert_wait_pending(server: &mut ReportServer) {
        let mut wait = Box::pin(server.wait());
        assert!(futures_util::poll!(wait.as_mut()).is_pending());
    }

    async fn deadline<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(3), future)
            .await
            .expect("deadline exceeded")
    }

    async fn round_trip_client(socket: &Path) {
        let mut conn = zlink::tokio::unix::connect(socket).await.expect("connect");
        let listed: Vec<_> = conn
            .list()
            .await
            .expect("list")
            .map(|r| r.expect("reply").expect("no error"))
            .collect()
            .await;
        assert!(listed.iter().any(
            |m| m.name == "io.monitord.collectorSuccess" && m.object.as_deref() == Some("pid1")
        ));
        assert!(listed
            .iter()
            .any(|m| m.name == "io.monitord.healthy" && m.value == serde_json::json!(1)));

        let described: Vec<Result<_, MetricsError>> = conn
            .describe()
            .await
            .expect("describe")
            .map(|r| r.expect("reply"))
            .collect()
            .await;
        assert_eq!(described.len(), FAMILIES.len());
        assert!(described.iter().all(Result::is_ok));
    }
}
