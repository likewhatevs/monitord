//! # report_collector module
//!
//! Collects `io.systemd.Metrics` sources from `/run/systemd/report/` (systemd
//! v260+) and configured commands, passing their metrics through as generic
//! key/value stats.
//!
//! Each socket in that directory is named after a varlink interface (e.g.
//! `io.systemd.Basic`), and every metric it serves must be named
//! `<socket name>.<field>`. Sources monitord already parses into typed stats
//! (`io.systemd.Manager`, `io.systemd.Network`) and monitord's own source
//! (`io.monitord`) are skipped during socket discovery. Configured commands
//! supply metric records or a single JSON number under their source name.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures_util::stream::TryStreamExt;
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;
use tracing::debug;
use tracing::warn;

use crate::config::{ReportCommand, ReportCommandFormat, ReportConfig};
use crate::varlink::metrics::{ListOutput, Metrics, MetricsError};
use crate::MonitordStats;

mod command_group;

/// Where systemd-report looks for system metrics sources.
pub const REPORT_DIR: &str = "/run/systemd/report";

/// Socket sources that are never collected here:
/// - `io.systemd.Manager` and `io.systemd.Network` already feed typed
///   collectors (`units`, `networkd`, ...).
/// - `io.monitord` is monitord itself.
/// - `io.systemd.CGroup` publishes per-cgroup metrics, hundreds of keys even
///   on a small host. It is left out until a dedicated change adds
///   per-cgroup filtering.
pub const SKIP_SOURCES: &[&str] = &[
    "io.systemd.Manager",
    "io.systemd.Network",
    "io.monitord",
    "io.systemd.CGroup",
];

/// Socket source prefixes that are never collected: `io.systemd.Report.*`
/// are systemd-report's own signers (`SignPlain`, `SignTPM2`, `SignTSM`),
/// which only publish their public key, not health.
pub const SKIP_SOURCE_PREFIXES: &[&str] = &["io.systemd.Report."];

/// Same per-source cap as systemd-report (`METRICS_PER_SOURCE_MAX`).
pub const METRICS_PER_SOURCE_MAX: usize = 16384;

/// Same socket source cap as systemd-report (`METRICS_LINKS_MAX`).
pub const SOURCES_MAX: usize = 128;

/// Maximum complete stdout of one command (one extra byte detects overflow).
const COMMAND_STDOUT_MAX: usize = 16 * 1024 * 1024;

/// Metrics from one report source.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ReportSource {
    /// Whether collection from this source succeeded this run
    pub up: bool,
    /// Metrics the source returned but that were dropped: names not prefixed
    /// with the source name, invalid names, or past the per-source cap
    pub dropped_metrics: u64,
    /// Metrics left out because one of their flat keys was already taken by
    /// an earlier metric, or repeated inside their own value. Keys are kept
    /// readable (unit names keep their dots), so two different metrics can
    /// map to the same key. The first one wins and later ones are counted
    /// here, never silently overwritten.
    pub colliding_metrics: u64,
    /// Metric values keyed by `<field>[.<object>][.<field>_<value>...]`,
    /// where the first `<field>` is the metric name without the source prefix
    pub metrics: BTreeMap<String, serde_json::Value>,
}

/// Report sources keyed by source name (e.g. `io.systemd.Basic`)
pub type ReportStats = BTreeMap<String, ReportSource>;

/// Varlink interface name check, as `varlink_idl_interface_name_is_valid()`:
/// dot-separated segments, at least two, the first starting with a letter,
/// each of alphanumerics with inner (never leading or trailing) dashes.
pub fn interface_name_is_valid(name: &str) -> bool {
    let segments: Vec<&str> = name.split('.').collect();
    if segments.len() < 2 {
        return false;
    }
    segments.iter().enumerate().all(|(idx, segment)| {
        let bytes = segment.as_bytes();
        let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
            return false;
        };
        let first_ok = if idx == 0 {
            first.is_ascii_alphabetic()
        } else {
            first.is_ascii_alphanumeric()
        };
        first_ok
            && last.is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    })
}

/// Varlink field name check, as `varlink_idl_field_name_is_valid()`: starts
/// with a letter, alphanumerics with single inner underscores.
pub fn field_name_is_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    first.is_ascii_alphabetic()
        && *last != b'_'
        && !name.contains("__")
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// Whether systemd-report would accept `metric_name` from `source`: an
/// interface name, a dot, then a field name, with the source as a true prefix.
pub fn metric_name_is_valid(metric_name: &str, source: &str) -> bool {
    let Some((interface, field)) = metric_name.rsplit_once('.') else {
        return false;
    };
    interface_name_is_valid(interface)
        && field_name_is_valid(field)
        && metric_name
            .strip_prefix(source)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Whether a socket name in the report directory should be collected.
///
/// `allowlist`/`blocklist` entries are compared case-insensitively and must
/// already be lowercase, as `configparser` hands them over.
pub fn should_collect_source(
    name: &str,
    allowlist: &HashSet<String>,
    blocklist: &HashSet<String>,
) -> bool {
    if !interface_name_is_valid(name)
        || SKIP_SOURCES.contains(&name)
        || SKIP_SOURCE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    {
        return false;
    }
    // The INI parser lowercases keys, so lists hold lowercased names.
    let lowered = name.to_lowercase();
    if blocklist.contains(&lowered) {
        return false;
    }
    allowlist.is_empty() || allowlist.contains(&lowered)
}

/// Whether `metric_name` is in `blocklist`, exactly or below an entry at a
/// dot boundary, so a family entry covers all of its sub-names.
///
/// Entries must already be lowercase, as `configparser` hands them over.
pub fn metric_is_blocked(metric_name: &str, blocklist: &HashSet<String>) -> bool {
    if blocklist.is_empty() {
        return false;
    }
    let lowered = metric_name.to_lowercase();
    let mut prefix = lowered.as_str();
    loop {
        if blocklist.contains(prefix) {
            return true;
        }
        match prefix.rsplit_once('.') {
            Some((parent, _)) => prefix = parent,
            None => return false,
        }
    }
}

/// Flat key for one metric: the name without the source prefix, then the
/// object, then every field as `<field>_<value>` in sorted field order.
fn metric_key(metric: &ListOutput, source: &str) -> String {
    let mut key = metric
        .name()
        .strip_prefix(source)
        .and_then(|rest| rest.strip_prefix('.'))
        .unwrap_or(metric.name())
        .to_string();
    if let Some(object) = metric.object() {
        key.push('.');
        key.push_str(object);
    }
    if let Some(fields) = metric.fields() {
        let sorted: BTreeMap<&String, &serde_json::Value> = fields.iter().collect();
        for (field, value) in sorted {
            let value = match value {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            key.push('.');
            key.push_str(field);
            key.push('_');
            key.push_str(&value);
        }
    }
    key
}

/// Bools become 0/1 at any depth, so every scalar is a number or a string,
/// like the rest of monitord's output. Objects and arrays keep their shape
/// for `json`/`json-pretty`; [`flat_leaves`] flattens them for `json-flat`.
fn normalize_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Bool(b) => u64::from(*b).into(),
        serde_json::Value::Object(members) => members
            .iter()
            .map(|(member, value)| (member.clone(), normalize_value(value)))
            .collect::<serde_json::Map<_, _>>()
            .into(),
        serde_json::Value::Array(items) => items.iter().map(normalize_value).collect(),
        other => other.clone(),
    }
}

/// The `json-flat` leaves of `value` stored at `key`: objects descend into
/// `key.<member>`, arrays into `key.<index>`, and nulls produce nothing.
///
/// `json.rs` uses this too, so the collision check in [`normalize_metrics`]
/// sees exactly the keys the flat output will hold.
pub fn flat_leaves(
    key: String,
    value: &serde_json::Value,
    out: &mut Vec<(String, serde_json::Value)>,
) {
    match value {
        serde_json::Value::Object(members) => {
            for (member, member_value) in members {
                flat_leaves(format!("{key}.{member}"), member_value, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                flat_leaves(format!("{key}.{idx}"), item, out);
            }
        }
        serde_json::Value::Null => {}
        scalar => out.push((key, scalar.clone())),
    }
}

/// Turn one source's metric records into a [`ReportSource`], dropping what
/// systemd-report would drop and skipping what `metric_blocklist` names.
///
/// Blocked metrics are left out on purpose, so they are not counted in
/// `dropped_metrics`, which flags metrics a source got wrong.
pub fn normalize_metrics(
    source: &str,
    metrics: &[ListOutput],
    metric_blocklist: &HashSet<String>,
) -> ReportSource {
    let mut report_source = ReportSource {
        up: true,
        ..Default::default()
    };
    // Every flat key taken so far, including the members of object values,
    // so a later metric can't land on (and overwrite) an earlier one.
    let mut taken: HashSet<String> = HashSet::new();
    for (idx, metric) in metrics.iter().enumerate() {
        if idx >= METRICS_PER_SOURCE_MAX || !metric_name_is_valid(metric.name(), source) {
            debug!("Dropping metric {:?} from report source {}", metric, source);
            report_source.dropped_metrics += 1;
            continue;
        }
        if metric.value().is_null() || metric_is_blocked(metric.name(), metric_blocklist) {
            continue;
        }
        let key = metric_key(metric, source);
        let value = normalize_value(metric.value());
        let mut leaves = Vec::new();
        flat_leaves(key.clone(), &value, &mut leaves);
        let mut own: HashSet<&str> = HashSet::with_capacity(leaves.len());
        let collides = report_source.metrics.contains_key(&key)
            || leaves
                .iter()
                .any(|(leaf, _)| taken.contains(leaf) || !own.insert(leaf.as_str()));
        if collides {
            warn!(
                "Report source {} metric {} maps to flat key {:?}, already in use; skipping it",
                source,
                metric.name(),
                key
            );
            report_source.colliding_metrics += 1;
            continue;
        }
        taken.extend(leaves.into_iter().map(|(leaf, _)| leaf));
        report_source.metrics.insert(key, value);
    }
    report_source
}

/// List the sources to collect, sorted, in `dir`.
pub async fn list_sources(
    dir: &Path,
    allowlist: &HashSet<String>,
    blocklist: &HashSet<String>,
) -> anyhow::Result<Vec<String>> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            debug!(
                "{} does not exist (systemd < v260?): no report sources",
                dir.display()
            );
            return Ok(Vec::new());
        }
        Err(err) => return Err(err.into()),
    };
    let mut sources = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        if !file_type.is_socket() && !file_type.is_symlink() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if should_collect_source(&name, allowlist, blocklist) {
            sources.push(name);
        }
    }
    sources.sort();
    if sources.len() > SOURCES_MAX {
        warn!(
            "Reached limit of {} report sources, skipping {}",
            SOURCES_MAX,
            sources.len() - SOURCES_MAX
        );
        sources.truncate(SOURCES_MAX);
    }
    Ok(sources)
}

/// Stream `io.systemd.Metrics.List` from one source socket.
///
/// Runs on a blocking thread with its own runtime for the same reason as
/// `varlink_units::collect_metrics`: the zlink stream is !Send. A source that
/// ends its stream with `NoSuchMetric` simply has nothing (more) to report.
async fn list_source(path: PathBuf, timeout: Duration) -> anyhow::Result<Vec<ListOutput>> {
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            tokio::time::timeout(timeout, async move {
                let mut conn = zlink::tokio::unix::connect(&path).await?;
                let stream = conn.list().await?;
                futures_util::pin_mut!(stream);
                let mut metrics = Vec::new();
                while let Some(reply) = stream.try_next().await? {
                    match reply {
                        Ok(metric) => metrics.push(metric),
                        Err(MetricsError::NoSuchMetric) => break,
                    }
                    // One past the cap is enough for normalize_metrics to
                    // count drops without buffering an unbounded stream.
                    if metrics.len() > METRICS_PER_SOURCE_MAX {
                        break;
                    }
                }
                Ok::<_, anyhow::Error>(metrics)
            })
            .await
            .map_err(|_| anyhow::anyhow!("timed out after {:?}", timeout))?
        })
    })
    .await?
}

fn number_metric(source: &str, value: serde_json::Value) -> ListOutput {
    ListOutput {
        name: format!("{source}.value"),
        value,
        object: None,
        fields: None,
    }
}

fn parse_command_output(
    source: &str,
    format: ReportCommandFormat,
    stdout: &[u8],
) -> anyhow::Result<(Vec<ListOutput>, u64)> {
    match format {
        ReportCommandFormat::Number => {
            let value: serde_json::Value =
                serde_json::from_slice(stdout).context("invalid JSON number")?;
            anyhow::ensure!(value.is_number(), "expected one finite JSON number");
            Ok((vec![number_metric(source, value)], 0))
        }
        ReportCommandFormat::Records => {
            let text = std::str::from_utf8(stdout).context("stdout is not UTF-8")?;
            let mut metrics = Vec::new();
            let mut dropped = 0;
            for (index, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let value: serde_json::Value = serde_json::from_str(line)
                    .with_context(|| format!("invalid JSON on line {}", index + 1))?;
                anyhow::ensure!(value.is_object(), "line {} is not a JSON object", index + 1);
                anyhow::ensure!(
                    value.get("value").is_some(),
                    "line {} has no value",
                    index + 1
                );
                let metric: ListOutput = serde_json::from_value(value)
                    .with_context(|| format!("invalid metric on line {}", index + 1))?;
                if metrics.len() < METRICS_PER_SOURCE_MAX {
                    metrics.push(metric);
                } else {
                    dropped += 1;
                }
            }
            anyhow::ensure!(!metrics.is_empty(), "stdout has no metrics");
            Ok((metrics, dropped))
        }
    }
}

/// Run inside the source's task, which outlives cancellation of collection.
/// Read stdout before waiting, including data written by descendants.
async fn run_command(command: ReportCommand, timeout: Duration) -> anyhow::Result<Vec<u8>> {
    run_command_inner(
        command,
        timeout,
        #[cfg(test)]
        None,
    )
    .await
}

#[cfg(test)]
struct CommandWaitGate {
    waiting: tokio::sync::oneshot::Sender<libc::pid_t>,
    resume: tokio::sync::oneshot::Receiver<()>,
}

async fn run_command_inner(
    command: ReportCommand,
    timeout: Duration,
    #[cfg(test)] wait_gate: Option<CommandWaitGate>,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        command.path.is_absolute(),
        "report command path must be absolute: {}",
        command.path.display()
    );
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .context("report command timeout exceeds the clock range")?;
    let (mut child, group) = command_group::CommandGroup::spawn(&command.path)
        .with_context(|| format!("unable to execute {}", command.path.display()))?;
    #[cfg(test)]
    let pgid = child.id().expect("a newly spawned child has an ID") as libc::pid_t;
    let mut stdout = Vec::new();
    let result = tokio::time::timeout_at(deadline, async {
        child
            .stdout
            .take()
            .expect("stdout is piped")
            .take(COMMAND_STDOUT_MAX as u64 + 1)
            .read_to_end(&mut stdout)
            .await
            .context("unable to read stdout")?;
        anyhow::ensure!(stdout.len() <= COMMAND_STDOUT_MAX, "stdout exceeds 16 MiB");
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let failure = match result {
        Ok(Ok(())) => {
            #[cfg(test)]
            if let Some(gate) = wait_gate {
                let _ = gate.waiting.send(pgid);
                let _ = gate.resume.await;
            }
            match tokio::time::timeout_at(deadline, child.wait()).await {
                Ok(status) => {
                    group.disarm();
                    let status = status.context("unable to reap command")?;
                    anyhow::ensure!(status.success(), "command exited with {status}");
                    return Ok(stdout);
                }
                Err(_) => anyhow::anyhow!("timed out after {timeout:?}"),
            }
        }
        Ok(Err(error)) => error,
        Err(_) => anyhow::anyhow!("timed out after {timeout:?}"),
    };
    let signal = group.kill();
    // Linux checks the signal recipient's credentials separately. If a helper
    // changed identity or cannot exit promptly, finish the sample and reap it
    // when it exits. Never fall back to signalling a numeric PID or group.
    match tokio::time::timeout(Duration::from_secs(1), child.wait()).await {
        Ok(status) => {
            signal.context("unable to signal failed command group")?;
            status.context("unable to reap failed command")?;
        }
        Err(_) => {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            signal.context("unable to signal failed command group")?;
            return Err(failure.context("command still running after process-group cleanup"));
        }
    }
    Err(failure)
}

async fn command_source(
    source: String,
    command: ReportCommand,
    metric_blocklist: HashSet<String>,
    timeout: Duration,
) -> (String, ReportSource) {
    let result = run_command(command.clone(), timeout)
        .await
        .and_then(|stdout| parse_command_output(&source, command.format, &stdout));
    let report_source = command_result(&source, command.format, &metric_blocklist, result);
    (source, report_source)
}

fn command_result(
    source: &str,
    format: ReportCommandFormat,
    metric_blocklist: &HashSet<String>,
    result: anyhow::Result<(Vec<ListOutput>, u64)>,
) -> ReportSource {
    match result {
        Ok((metrics, dropped)) => {
            let mut result = normalize_metrics(source, &metrics, metric_blocklist);
            if dropped > 0 {
                debug!("Dropped {dropped} records over the limit from report command {source}");
                result.dropped_metrics += dropped;
            }
            result
        }
        Err(error) => {
            warn!("Unable to collect report source {}: {:#}", source, error);
            let mut failed = match format {
                ReportCommandFormat::Number => {
                    normalize_metrics(source, &[number_metric(source, 0.into())], metric_blocklist)
                }
                ReportCommandFormat::Records => ReportSource::default(),
            };
            failed.up = false;
            failed
        }
    }
}

/// Collect admitted sockets in `dir` and configured commands concurrently.
/// Command keys that are invalid Varlink interface names are skipped.
/// A failing source reports `up: false` and never fails the collector. Commands
/// outlive cancellation of this future until they finish or time out; their late
/// results are discarded. Shutting down the runtime signals in-flight command
/// groups. Keep the runtime alive until completion to wait for their status.
pub async fn collect_report_stats(
    dir: &Path,
    config: &ReportConfig,
    timeout: Duration,
) -> anyhow::Result<ReportStats> {
    let sources = list_sources(dir, &config.allowlist, &config.blocklist).await?;
    let socket_names: HashSet<_> = sources.iter().map(|name| name.to_lowercase()).collect();
    let mut commands = Vec::new();
    for (name, command) in &config.commands {
        if !interface_name_is_valid(name) {
            warn!("Skipping report command {name:?}: invalid Varlink interface name");
            continue;
        }
        if socket_names.contains(&name.to_lowercase()) {
            warn!(
                "Skipping report command {}: a listed socket has the same name",
                name
            );
            continue;
        }
        commands.push(tokio::spawn(command_source(
            name.clone(),
            command.clone(),
            config.metric_blocklist.clone(),
            timeout,
        )));
    }
    let results = futures_util::future::join_all(
        sources
            .iter()
            .map(|source| list_source(dir.join(source), timeout)),
    )
    .await;

    let mut stats = ReportStats::new();
    for (source, result) in sources.into_iter().zip(results) {
        let report_source = match result {
            Ok(metrics) => normalize_metrics(&source, &metrics, &config.metric_blocklist),
            Err(err) => {
                warn!("Unable to collect report source {}: {:#}", source, err);
                ReportSource::default()
            }
        };
        stats.insert(source, report_source);
    }
    for result in futures_util::future::join_all(commands).await {
        let (source, report_source) = result.context("report command task failed")?;
        stats.insert(source, report_source);
    }
    Ok(stats)
}

/// Collector entry point: replace `MonitordStats::report` with this run's sources.
pub async fn update_report_stats(
    config: Arc<crate::config::Config>,
    locked_monitord_stats: Arc<RwLock<MonitordStats>>,
) -> anyhow::Result<()> {
    let stats = collect_report_stats(
        Path::new(REPORT_DIR),
        &config.report,
        Duration::from_secs(config.monitord.dbus_timeout),
    )
    .await?;
    locked_monitord_stats.write().await.report = Some(stats);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    fn metric(
        name: &str,
        object: Option<&str>,
        fields: Option<&[(&str, serde_json::Value)]>,
        value: serde_json::Value,
    ) -> ListOutput {
        ListOutput {
            name: name.to_string(),
            value,
            object: object.map(str::to_string),
            fields: fields.map(|f| {
                f.iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect::<HashMap<_, _>>()
            }),
        }
    }

    #[test]
    fn test_interface_name_is_valid() {
        for valid in ["io.systemd.Basic", "io.monitord", "a.b", "org.foo-bar.X1"] {
            assert!(interface_name_is_valid(valid), "{valid}");
        }
        for invalid in [
            "",
            "io",
            "io.",
            ".io",
            "1io.systemd",
            "io.-systemd",
            "io.systemd-",
            "io.sys_temd",
            "io..systemd",
        ] {
            assert!(!interface_name_is_valid(invalid), "{invalid}");
        }
    }

    #[test]
    fn test_field_name_is_valid() {
        for valid in ["UnitsTotal", "unitActiveState", "a_b", "x1"] {
            assert!(field_name_is_valid(valid), "{valid}");
        }
        for invalid in ["", "_a", "a_", "a__b", "1a", "a-b", "a.b"] {
            assert!(!field_name_is_valid(invalid), "{invalid}");
        }
    }

    #[test]
    fn test_metric_name_is_valid() {
        assert!(metric_name_is_valid(
            "io.systemd.Basic.BootId",
            "io.systemd.Basic"
        ));
        assert!(metric_name_is_valid(
            "io.systemd.Basic.Sub.Value",
            "io.systemd.Basic"
        ));
        // Not prefixed by the source it came from
        assert!(!metric_name_is_valid(
            "io.systemd.Other.BootId",
            "io.systemd.Basic"
        ));
        // A prefix only counts at a dot boundary
        assert!(!metric_name_is_valid(
            "io.systemd.BasicX.BootId",
            "io.systemd.Basic"
        ));
        // The source name alone is not a metric
        assert!(!metric_name_is_valid(
            "io.systemd.Basic",
            "io.systemd.Basic"
        ));
        assert!(!metric_name_is_valid(
            "io.systemd.Basic.bad-field",
            "io.systemd.Basic"
        ));
    }

    #[test]
    fn test_should_collect_source() {
        let empty = HashSet::new();
        assert!(should_collect_source("io.systemd.Basic", &empty, &empty));
        for skipped in SKIP_SOURCES {
            assert!(!should_collect_source(skipped, &empty, &empty), "{skipped}");
        }
        assert!(!should_collect_source("not-an-interface", &empty, &empty));
        // systemd-report's signers only publish their public key
        assert!(!should_collect_source(
            "io.systemd.Report.SignPlain",
            &empty,
            &empty
        ));
        assert!(!should_collect_source(
            "io.systemd.Report.SignTPM2",
            &empty,
            &empty
        ));
        // The prefix is a true prefix: a source merely named alike is kept
        assert!(should_collect_source("io.systemd.Reporter", &empty, &empty));

        let allow = HashSet::from([String::from("io.systemd.basic")]);
        assert!(should_collect_source("io.systemd.Basic", &allow, &empty));
        assert!(!should_collect_source(
            "io.systemd.DiskSpace",
            &allow,
            &empty
        ));
        // Allowlisting a skipped source does not bring it back
        let allow_manager = HashSet::from([String::from("io.systemd.manager")]);
        assert!(!should_collect_source(
            "io.systemd.Manager",
            &allow_manager,
            &empty
        ));

        // Blocklist wins over allowlist
        assert!(!should_collect_source("io.systemd.Basic", &allow, &allow));
    }

    #[test]
    fn test_normalize_metrics() {
        let source = "io.systemd.Basic";
        let metrics = vec![
            metric(
                "io.systemd.Basic.Hostname",
                None,
                None,
                serde_json::json!("box"),
            ),
            metric(
                "io.systemd.Basic.UnitActive",
                Some("foo.service"),
                None,
                serde_json::json!(true),
            ),
            metric(
                "io.systemd.Basic.Bytes",
                Some("sda"),
                Some(&[
                    ("op", serde_json::json!("write")),
                    ("cpu", serde_json::json!(0)),
                ]),
                serde_json::json!(4096),
            ),
            metric(
                "io.systemd.Basic.Info",
                None,
                None,
                serde_json::json!({"a": 1}),
            ),
            metric(
                "io.systemd.Basic.Nothing",
                None,
                None,
                serde_json::Value::Null,
            ),
            // Wrong prefix and invalid field: both dropped
            metric("io.systemd.Other.Value", None, None, serde_json::json!(1)),
            metric(
                "io.systemd.Basic.bad-name",
                None,
                None,
                serde_json::json!(1),
            ),
        ];
        let normalized = normalize_metrics(source, &metrics, &HashSet::new());
        assert!(normalized.up);
        assert_eq!(normalized.dropped_metrics, 2);
        assert_eq!(
            normalized.metrics,
            BTreeMap::from([
                ("Hostname".to_string(), serde_json::json!("box")),
                ("UnitActive.foo.service".to_string(), serde_json::json!(1)),
                // Fields sort by name: cpu before op
                (
                    "Bytes.sda.cpu_0.op_write".to_string(),
                    serde_json::json!(4096)
                ),
                ("Info".to_string(), serde_json::json!({"a": 1})),
            ])
        );
    }

    #[test]
    fn test_metric_is_blocked() {
        let blocklist = HashSet::from([
            "io.systemd.basic.machineid".to_string(),
            "io.systemd.basic.smbios".to_string(),
        ]);
        assert!(metric_is_blocked("io.systemd.Basic.MachineID", &blocklist));
        // A family entry covers every name below it at a dot boundary
        assert!(metric_is_blocked(
            "io.systemd.Basic.SMBIOS.SystemProductName",
            &blocklist
        ));
        // ...but not names that merely share its text
        assert!(!metric_is_blocked("io.systemd.Basic.SMBIOSish", &blocklist));
        assert!(!metric_is_blocked(
            "io.systemd.Basic.MachineIDs",
            &blocklist
        ));
        assert!(!metric_is_blocked(
            "io.systemd.Basic.CPUsOnline",
            &blocklist
        ));
        assert!(!metric_is_blocked(
            "io.systemd.Basic.MachineID",
            &HashSet::new()
        ));
    }

    #[test]
    fn test_normalize_metrics_skips_blocked_without_counting_drops() {
        let metrics = vec![
            metric(
                "io.systemd.Basic.MachineID",
                None,
                None,
                serde_json::json!("7000"),
            ),
            metric(
                "io.systemd.Basic.SMBIOS.SystemVendor",
                None,
                None,
                serde_json::json!("acme"),
            ),
            metric(
                "io.systemd.Basic.CPUsOnline",
                None,
                None,
                serde_json::json!(4),
            ),
        ];
        let blocklist = HashSet::from([
            "io.systemd.basic.machineid".to_string(),
            "io.systemd.basic.smbios".to_string(),
        ]);
        let normalized = normalize_metrics("io.systemd.Basic", &metrics, &blocklist);
        assert_eq!(normalized.dropped_metrics, 0);
        assert_eq!(
            normalized.metrics,
            BTreeMap::from([("CPUsOnline".to_string(), serde_json::json!(4))])
        );
    }

    #[test]
    fn test_normalize_metrics_counts_dimension_collisions() {
        // Different field sets that render to the same key: Value.x_a.y_b
        let metrics = vec![
            metric(
                "io.systemd.Basic.Value",
                None,
                Some(&[("x", serde_json::json!("a")), ("y", serde_json::json!("b"))]),
                serde_json::json!(1),
            ),
            metric(
                "io.systemd.Basic.Value",
                None,
                Some(&[("x", serde_json::json!("a.y_b"))]),
                serde_json::json!(2),
            ),
            // An object name that renders like a field suffix
            metric(
                "io.systemd.Basic.Value",
                Some("x_a.y_b"),
                None,
                serde_json::json!(3),
            ),
        ];
        let normalized = normalize_metrics("io.systemd.Basic", &metrics, &HashSet::new());
        assert_eq!(normalized.colliding_metrics, 2);
        assert_eq!(normalized.dropped_metrics, 0);
        // The first metric keeps its value instead of being overwritten
        assert_eq!(
            normalized.metrics,
            BTreeMap::from([("Value.x_a.y_b".to_string(), serde_json::json!(1))])
        );
    }

    #[test]
    fn test_normalize_metrics_counts_flattened_path_collisions() {
        let metrics = vec![
            // Collides with itself: {"a": {"b": 1}} and "a.b" both flatten
            // to Info.a.b
            metric(
                "io.systemd.Basic.Info",
                None,
                None,
                serde_json::json!({"a": {"b": 1}, "a.b": 2}),
            ),
            // A plain metric whose key is one of a later object's leaves
            metric(
                "io.systemd.Basic.Other",
                Some("a"),
                None,
                serde_json::json!(3),
            ),
            metric(
                "io.systemd.Basic.Other",
                None,
                None,
                serde_json::json!({"a": 4, "b": 5}),
            ),
        ];
        let normalized = normalize_metrics("io.systemd.Basic", &metrics, &HashSet::new());
        assert_eq!(normalized.colliding_metrics, 2);
        assert_eq!(
            normalized.metrics,
            BTreeMap::from([("Other.a".to_string(), serde_json::json!(3))])
        );
    }

    #[test]
    fn test_normalize_metrics_converts_nested_booleans() {
        let metrics = vec![metric(
            "io.systemd.Basic.Info",
            None,
            None,
            serde_json::json!({"enabled": true, "flags": [false, true], "inner": {"on": false}}),
        )];
        let normalized = normalize_metrics("io.systemd.Basic", &metrics, &HashSet::new());
        assert_eq!(
            normalized.metrics["Info"],
            serde_json::json!({"enabled": 1, "flags": [0, 1], "inner": {"on": 0}})
        );
    }

    #[test]
    fn test_normalize_metrics_caps_per_source() {
        let metrics: Vec<ListOutput> = (0..METRICS_PER_SOURCE_MAX + 2)
            .map(|i| {
                metric(
                    "io.systemd.Basic.Value",
                    Some(&format!("o{i}")),
                    None,
                    serde_json::json!(i),
                )
            })
            .collect();
        let normalized = normalize_metrics("io.systemd.Basic", &metrics, &HashSet::new());
        assert_eq!(normalized.metrics.len(), METRICS_PER_SOURCE_MAX);
        assert_eq!(normalized.dropped_metrics, 2);
    }

    #[tokio::test]
    async fn test_list_sources_filters_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _basic =
            std::os::unix::net::UnixListener::bind(dir.path().join("io.systemd.Basic")).unwrap();
        let _manager =
            std::os::unix::net::UnixListener::bind(dir.path().join("io.systemd.Manager")).unwrap();
        let _bad = std::os::unix::net::UnixListener::bind(dir.path().join("bad")).unwrap();
        std::fs::write(dir.path().join("io.systemd.File"), b"").unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("io.systemd.Basic"),
            dir.path().join("io.systemd.Link"),
        )
        .unwrap();

        let empty = HashSet::new();
        let sources = list_sources(dir.path(), &empty, &empty).await.unwrap();
        assert_eq!(sources, vec!["io.systemd.Basic", "io.systemd.Link"]);

        let missing = list_sources(&dir.path().join("nope"), &empty, &empty)
            .await
            .unwrap();
        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn test_collect_report_stats_marks_dead_source_down() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Serves two metrics then ends the stream
        let good = tokio::net::UnixListener::bind(dir.path().join("io.example.Good")).unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = good.accept().await.expect("accept");
            let mut request = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut request).await;
            tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                b"{\"parameters\":{\"name\":\"io.example.Good.Value\",\"value\":1},\"continues\":true}\0\
                  {\"parameters\":{\"name\":\"io.example.Good.Other\",\"object\":\"x\",\"value\":\"y\"}}\0",
            )
            .await
            .expect("write reply");
        });
        crate::tests::bind_stale_socket(&dir.path().join("io.example.Dead"));

        let stats =
            collect_report_stats(dir.path(), &ReportConfig::default(), Duration::from_secs(5))
                .await
                .unwrap();
        server.await.expect("server");

        assert_eq!(stats.len(), 2);
        assert_eq!(stats["io.example.Dead"], ReportSource::default());
        let good = &stats["io.example.Good"];
        assert!(good.up);
        assert_eq!(good.metrics["Value"], serde_json::json!(1));
        assert_eq!(good.metrics["Other.x"], serde_json::json!("y"));
    }

    fn write_executable_fixture(path: &Path, contents: &str) {
        // Write in a separate process so another test's fork cannot inherit
        // the writable descriptor and make exec fail with ETXTBSY.
        let status = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                r#"printf '%s' "$1" > "$2""#,
                "write-fixture",
                contents,
            ])
            .arg(path)
            .status()
            .expect("write executable fixture");
        assert!(status.success(), "writing {}: {status}", path.display());
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn command_fixture(
        dir: &Path,
        name: &str,
        body: &str,
        format: ReportCommandFormat,
    ) -> ReportCommand {
        let path = dir.join(name);
        write_executable_fixture(&path, &format!("#!/bin/sh\n{body}\n"));
        ReportCommand { path, format }
    }

    fn command_config(command: ReportCommand) -> ReportConfig {
        ReportConfig {
            commands: BTreeMap::from([("com.example.check".to_string(), command)]),
            ..Default::default()
        }
    }

    #[test]
    fn test_command_output_requires_complete_valid_shape() {
        for output in [
            b"".as_slice(),
            b" \n",
            b"[]",
            br#"["com.example.check.a", 1, null, null]"#,
            br#"{"name":"com.example.check.a"}"#,
            b"{}",
            br#"{"name":1,"value":0}"#,
            br#"{"name":"com.example.check.a","value":0}
junk"#,
        ] {
            assert!(
                parse_command_output("com.example.check", ReportCommandFormat::Records, output)
                    .is_err(),
                "{output:?}"
            );
        }
        for output in [
            "", "true", "\"1\"", "null", "NaN", "Infinity", "1e999", "1 2",
        ] {
            assert!(
                parse_command_output(
                    "com.example.check",
                    ReportCommandFormat::Number,
                    output.as_bytes()
                )
                .is_err(),
                "{output}"
            );
        }
        let record = r#"{"name":"com.example.check.a","value":1}"#;
        let mut output = format!("{record}\n").repeat(METRICS_PER_SOURCE_MAX + 1);
        let (retained, dropped) = parse_command_output(
            "com.example.check",
            ReportCommandFormat::Records,
            output.as_bytes(),
        )
        .unwrap();
        assert_eq!(retained.len(), METRICS_PER_SOURCE_MAX);
        assert_eq!(dropped, 1);
        output.push_str("bad line\n");
        assert!(parse_command_output(
            "com.example.check",
            ReportCommandFormat::Records,
            output.as_bytes()
        )
        .is_err());
    }

    #[tokio::test]
    async fn test_command_requires_absolute_path() {
        for path in ["true", "./true"] {
            let command = ReportCommand {
                path: path.into(),
                format: ReportCommandFormat::Number,
            };
            let error = run_command(command, Duration::from_secs(5))
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("path must be absolute"),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn test_command_deadline_overflow_marks_source_down() {
        let dir = tempfile::tempdir().unwrap();
        let command = command_fixture(
            dir.path(),
            "helper",
            "printf 7",
            ReportCommandFormat::Number,
        );
        let stats = collect_report_stats(
            dir.path(),
            &command_config(command),
            Duration::from_secs(u64::MAX),
        )
        .await
        .unwrap();
        let source = &stats["com.example.check"];
        assert!(!source.up);
        assert_eq!(source.metrics["value"], 0);
    }

    #[tokio::test]
    async fn test_command_success_and_failure_rules() {
        let dir = tempfile::tempdir().unwrap();
        for (index, (body, format, up, value)) in [
            ("printf '0\\n'", ReportCommandFormat::Number, true, Some(0)),
            (
                "printf '5'; exit 1",
                ReportCommandFormat::Number,
                false,
                Some(0),
            ),
            ("printf 'bad'", ReportCommandFormat::Number, false, Some(0)),
            (
                r#"printf '{"name":"com.example.check.value","value":2}\n'"#,
                ReportCommandFormat::Records,
                true,
                Some(2),
            ),
            (
                r#"printf '{"name":"com.example.check.value","value":2}\nbad'"#,
                ReportCommandFormat::Records,
                false,
                None,
            ),
            (
                r#"printf '{"name":"com.example.check.value","value":2}\n'; exit 1"#,
                ReportCommandFormat::Records,
                false,
                None,
            ),
            ("exit 0", ReportCommandFormat::Records, false, None),
        ]
        .into_iter()
        .enumerate()
        {
            let command = command_fixture(dir.path(), &format!("helper{index}"), body, format);
            let stats = collect_report_stats(
                &dir.path().join("missing"),
                &command_config(command),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let source = &stats["com.example.check"];
            assert_eq!(source.up, up, "case {index}");
            assert_eq!(
                source.metrics.get("value"),
                value.map(serde_json::Value::from).as_ref(),
                "case {index}"
            );
        }
        let command = command_fixture(dir.path(), "fail", "exit 1", ReportCommandFormat::Number);
        let mut config = command_config(command);
        config
            .metric_blocklist
            .insert("com.example.check.value".into());
        let stats = collect_report_stats(dir.path(), &config, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(!stats["com.example.check"].up);
        assert!(stats["com.example.check"].metrics.is_empty());
    }

    #[tokio::test]
    async fn test_command_socket_collision_and_directory_errors() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("started");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!("touch '{}'; printf 3", marker.display()),
            ReportCommandFormat::Number,
        );
        let mut config = command_config(command);
        // Names clash case-insensitively; even a dead admitted socket wins.
        crate::tests::bind_stale_socket(&dir.path().join("com.example.Check"));
        let stats = collect_report_stats(dir.path(), &config, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(stats.len(), 1);
        assert!(!stats["com.example.Check"].up);
        assert!(!marker.exists());
        config.blocklist.insert("com.example.check".into());
        let stats = collect_report_stats(dir.path(), &config, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(stats["com.example.check"].up);
        assert!(marker.exists());
        std::fs::remove_file(&marker).unwrap();
        let file = dir.path().join("not-directory");
        std::fs::write(&file, "").unwrap();
        assert!(collect_report_stats(&file, &config, Duration::from_secs(5))
            .await
            .is_err());
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn test_commands_only_run_for_valid_interface_names() {
        let dir = tempfile::tempdir().unwrap();
        let calls = dir.path().join("calls");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!("printf x >> '{}'; printf 7", calls.display()),
            ReportCommandFormat::Number,
        );
        let config = ReportConfig {
            commands: BTreeMap::from([
                ("bad name".into(), command.clone()),
                ("com.example.Check".into(), command),
            ]),
            ..Default::default()
        };
        let stats = collect_report_stats(dir.path(), &config, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats["com.example.Check"].metrics["value"], 7);
        assert_eq!(std::fs::read_to_string(calls).unwrap(), "x");
    }

    #[tokio::test]
    async fn test_commands_ignore_socket_filters_and_reserved_names() {
        let dir = tempfile::tempdir().unwrap();
        let command = command_fixture(
            dir.path(),
            "helper",
            "printf 7",
            ReportCommandFormat::Number,
        );
        let names: Vec<_> = SKIP_SOURCES
            .iter()
            .map(|name| name.to_lowercase())
            .chain(std::iter::once("io.systemd.report.signplain".to_string()))
            .collect();
        let config = ReportConfig {
            commands: names
                .iter()
                .map(|name| (name.clone(), command.clone()))
                .collect(),
            allowlist: HashSet::from(["com.example.unrelated".to_string()]),
            blocklist: names.iter().cloned().collect(),
            ..Default::default()
        };
        let stats = collect_report_stats(dir.path(), &config, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(stats.len(), names.len());
        for name in names {
            assert!(stats[&name].up, "{name}");
            assert_eq!(stats[&name].metrics["value"], 7, "{name}");
        }
    }

    #[tokio::test]
    async fn test_command_stdout_limit_includes_every_byte() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("output");
        for (format, value) in [
            (ReportCommandFormat::Number, "7"),
            (
                ReportCommandFormat::Records,
                r#"{"name":"com.example.check.value","value":7}"#,
            ),
        ] {
            let command = command_fixture(
                dir.path(),
                "helper",
                &format!("cat '{}'", output.display()),
                format,
            );
            let mut bytes = vec![b' '; COMMAND_STDOUT_MAX];
            bytes[..value.len()].copy_from_slice(value.as_bytes());
            std::fs::write(&output, &bytes).unwrap();
            let read = run_command(command.clone(), Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(read.len(), COMMAND_STDOUT_MAX);
            assert_eq!(
                parse_command_output("com.example.check", format, &read)
                    .unwrap()
                    .0[0]
                    .value,
                7
            );
            bytes.push(b' ');
            std::fs::write(&output, &bytes).unwrap();
            assert!(run_command(command, Duration::from_secs(5))
                .await
                .unwrap_err()
                .to_string()
                .contains("16 MiB"));
        }
    }

    // These process tests pause Tokio's clock until the real helper signals
    // readiness. Keep a runnable task while polling the OS so Tokio cannot
    // auto-advance to the command deadline before the helper gets CPU. A real
    // wall-clock deadline still bounds a broken helper or failed cleanup.
    #[cfg(target_os = "linux")]
    async fn wait_for_process_event<T>(
        description: &str,
        mut check: impl FnMut() -> Option<T>,
    ) -> T {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(value) = check() {
                return value;
            }
            assert!(std::time::Instant::now() < deadline, "{description}");
            tokio::task::yield_now().await;
            std::thread::yield_now();
        }
    }

    #[cfg(target_os = "linux")]
    async fn reap_command_leader(pid: libc::pid_t) {
        use rustix::process::{waitpid, Pid, WaitOptions};

        let leader = Pid::from_raw(pid).unwrap();
        wait_for_process_event("external reaper did not reap the leader", || {
            waitpid(Some(leader), WaitOptions::NOHANG).unwrap()
        })
        .await;
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_process_state(pid: u32, gone: bool) {
        wait_for_process_event("command process did not exit/reap before deadline", || {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
            let ready = if gone {
                stat.is_err()
            } else {
                stat.as_ref().map_or(true, |s| {
                    s.split(") ").nth(1).is_some_and(|s| s.starts_with('Z'))
                })
            };
            ready.then_some(())
        })
        .await;
    }

    #[cfg(target_os = "linux")]
    async fn read_pids(path: &Path) -> Vec<u32> {
        wait_for_process_event("helper never started", || {
            let text = std::fs::read_to_string(path).ok()?;
            text.ends_with('\n').then(|| {
                text.split_whitespace()
                    .map(|s| s.parse().unwrap())
                    .collect()
            })
        })
        .await
    }

    #[cfg(target_os = "linux")]
    async fn finish_command(
        task: tokio::task::JoinHandle<anyhow::Result<Vec<u8>>>,
    ) -> anyhow::Result<Vec<u8>> {
        wait_for_process_event("command task did not finish before deadline", || {
            task.is_finished().then_some(())
        })
        .await;
        task.await.unwrap()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn test_command_finishing_just_before_deadline_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let release = dir.path().join("release");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!(
                r#"printf '%s\n' "$$" > '{}'
while [ -d '{}' ] && [ ! -e '{}' ]; do sleep 0.01; done
printf 7"#,
                pids.display(),
                dir.path().display(),
                release.display()
            ),
            ReportCommandFormat::Number,
        );
        let task = tokio::spawn(run_command(command, Duration::from_secs(1)));
        let ids = read_pids(&pids).await;
        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(!task.is_finished());
        std::fs::write(release, "").unwrap();
        let result = finish_command(task).await;
        assert_eq!(result.unwrap(), b"7");
        wait_for_process_state(ids[0], true).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_cancelling_command_task_signals_group() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!("echo $$ > '{}'\nexec sleep 5", pids.display()),
            ReportCommandFormat::Records,
        );
        let task = tokio::spawn(run_command(command, Duration::from_secs(15)));
        let ids = read_pids(&pids).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_process_state(ids[0], false),
        )
        .await
        .expect("cancelled helper outlived its task");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn test_command_wait_error_does_not_signal_group() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!(
                r#"while [ -d '{}' ]; do sleep 0.02; done >/dev/null &
printf '%s %s\n' "$$" "$!" > '{}'
printf 7"#,
                dir.path().display(),
                pids.display()
            ),
            ReportCommandFormat::Number,
        );
        let (waiting, mut at_wait) = tokio::sync::oneshot::channel();
        let (resume, gate) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_command_inner(
            command,
            Duration::from_secs(1),
            Some(CommandWaitGate {
                waiting,
                resume: gate,
            }),
        ));
        let ids = read_pids(&pids).await;
        let leader =
            wait_for_process_event("command never reached wait", || at_wait.try_recv().ok()).await;
        assert_eq!(leader, ids[0] as libc::pid_t);

        // Keep a live group member so an erroneous group kill is observable.
        reap_command_leader(leader).await;
        resume.send(()).unwrap();
        let error = finish_command(task).await.unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ECHILD)
        );
        let source = command_result(
            "com.example.check",
            ReportCommandFormat::Number,
            &HashSet::new(),
            Err(error),
        );
        assert!(!source.up);
        assert_eq!(source.metrics["value"], 0);
        let descendant = std::fs::read_to_string(format!("/proc/{}/stat", ids[1])).unwrap();
        let fields: Vec<_> = descendant
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        assert_ne!(fields[0], "Z", "{descendant}");
        assert_eq!(fields[2].parse::<libc::pid_t>().unwrap(), leader);
        drop(dir);
        wait_for_process_state(ids[1], false).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn test_command_timeout_signals_stopped_group_after_external_reap() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!(
                // The independent deadline also ends the stopped fixture if the test panics.
                r#"timeout --foreground -s KILL 60 sh -c 'printf "%s %s\n" "$1" "$$" > "$2"; kill -STOP $$' sh "$$" '{}' &"#,
                pids.display()
            ),
            ReportCommandFormat::Number,
        );
        let task = tokio::spawn(run_command(command, Duration::from_secs(1)));
        let ids = read_pids(&pids).await;
        let leader = ids[0] as libc::pid_t;
        wait_for_process_event("descendant never stopped", || {
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", ids[1])).ok()?;
            stat.rsplit_once(") ")?.1.starts_with("T ").then_some(())
        })
        .await;
        reap_command_leader(leader).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = finish_command(task).await.unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ECHILD)
        );
        wait_for_process_state(ids[1], false).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn test_command_timeout_kills_group_after_leader_exits() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!(
                r#"sleep 60 &
printf '%s %s\n' "$$" "$!" > '{}'
exit 0"#,
                pids.display()
            ),
            ReportCommandFormat::Number,
        );
        let task = tokio::spawn(run_command(command, Duration::from_secs(1)));
        let ids = read_pids(&pids).await;
        wait_for_process_state(ids[0], false).await;
        // Leader remains a zombie until group cleanup; its PID cannot be reused.
        assert!(std::fs::read_to_string(format!("/proc/{}/stat", ids[0]))
            .unwrap()
            .contains(") Z "));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(finish_command(task)
            .await
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        wait_for_process_state(ids[0], true).await;
        wait_for_process_state(ids[1], false).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn test_dropped_collection_still_kills_and_reaps_command() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!(
                r#"printf '%s\n' "$$" > '{}'
exec sleep 60"#,
                pids.display()
            ),
            ReportCommandFormat::Number,
        );
        let config = command_config(command);
        let path = dir.path().to_owned();
        let collection = tokio::spawn(async move {
            collect_report_stats(&path, &config, Duration::from_secs(1)).await
        });
        let ids = read_pids(&pids).await;
        collection.abort();
        assert!(collection.await.unwrap_err().is_cancelled());
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for_process_state(ids[0], true).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn test_command_overflow_kills_and_reaps_group() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!(
                r#"sleep 60 &
printf '%s %s\n' "$$" "$!" > '{}'
exec yes"#,
                pids.display()
            ),
            ReportCommandFormat::Records,
        );
        let task = tokio::spawn(run_command(command, Duration::from_secs(5)));
        let ids = read_pids(&pids).await;
        assert!(finish_command(task)
            .await
            .unwrap_err()
            .to_string()
            .contains("16 MiB"));
        wait_for_process_state(ids[0], true).await;
        wait_for_process_state(ids[1], false).await;
    }

    #[tokio::test]
    async fn test_command_and_socket_outputs_match() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("com.example.check");
        let socket = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let record = r#"{"name":"com.example.check.value","value":{"healthy":true,"count":3},"object":"a.b","fields":{"mode":"fast"}}"#;
        let reply = format!("{{\"parameters\":{record}}}\0");
        let server = tokio::spawn(async move {
            let (mut stream, _) = socket.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            tokio::io::AsyncWriteExt::write_all(&mut stream, reply.as_bytes())
                .await
                .unwrap();
        });
        let socket_stats =
            collect_report_stats(dir.path(), &ReportConfig::default(), Duration::from_secs(5))
                .await
                .unwrap();
        server.await.unwrap();
        std::fs::remove_file(socket_path).unwrap();
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!("printf '%s\\n' '{record}'"),
            ReportCommandFormat::Records,
        );
        let command_stats =
            collect_report_stats(dir.path(), &command_config(command), Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(command_stats, socket_stats);
        assert!(command_stats["com.example.check"].up);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn test_command_timeout_after_stdout_closes_reaps_leader() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let command = command_fixture(
            dir.path(),
            "helper",
            &format!(
                r#"exec >/dev/null
printf '%s\n' "$$" > '{}'
exec sleep 60"#,
                pids.display()
            ),
            ReportCommandFormat::Number,
        );
        let task = tokio::spawn(run_command(command, Duration::from_secs(1)));
        let ids = read_pids(&pids).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(finish_command(task)
            .await
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        wait_for_process_state(ids[0], true).await;
    }

    #[tokio::test]
    async fn test_commands_do_not_invoke_a_shell_for_scripts_without_shebang() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper");
        write_executable_fixture(&path, "printf 123\n");
        let config = command_config(ReportCommand {
            path,
            format: ReportCommandFormat::Number,
        });
        let stats = collect_report_stats(dir.path(), &config, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(!stats["com.example.check"].up);
        assert_eq!(stats["com.example.check"].metrics["value"], 0);
    }

    #[tokio::test]
    async fn test_commands_treat_spaces_as_part_of_the_executable_path() {
        let dir = tempfile::tempdir().unwrap();
        let command = command_fixture(
            dir.path(),
            "helper --not-an-argument",
            r#"[ "$#" -eq 0 ] || exit 1
printf 7"#,
            ReportCommandFormat::Number,
        );
        let stats =
            collect_report_stats(dir.path(), &command_config(command), Duration::from_secs(5))
                .await
                .unwrap();
        assert!(stats["com.example.check"].up);
        assert_eq!(stats["com.example.check"].metrics["value"], 7);
    }
}
