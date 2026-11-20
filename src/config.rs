use std::collections::BTreeMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;

use configparser::ini::Ini;
use indexmap::map::IndexMap;
use int_enum::IntEnum;
use smart_default::SmartDefault;
use strum_macros::EnumString;
use thiserror::Error;
use tracing::{error, warn};

#[derive(Error, Debug)]
pub enum MonitordConfigError {
    #[error("Invalid value for '{key}' in '{section}': {reason}")]
    InvalidValue {
        section: String,
        key: String,
        reason: String,
    },
    #[error("Missing key '{key}' in '{section}'")]
    MissingKey { section: String, key: String },
}

#[derive(Clone, Debug, Default, EnumString, Eq, IntEnum, PartialEq, strum_macros::Display)]
#[repr(u8)]
pub enum MonitordOutputFormat {
    #[default]
    #[strum(serialize = "json", serialize = "JSON", serialize = "Json")]
    Json = 0,
    #[strum(
        serialize = "json-flat",
        serialize = "json_flat",
        serialize = "jsonflat"
    )]
    JsonFlat = 1,
    #[strum(
        serialize = "json-pretty",
        serialize = "json_pretty",
        serialize = "jsonpretty"
    )]
    JsonPretty = 2,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct MonitordConfig {
    #[default(crate::DEFAULT_DBUS_ADDRESS.into())]
    pub dbus_address: String,
    pub daemon: bool,
    #[default = 30]
    pub daemon_stats_refresh_secs: u64,
    pub key_prefix: String,
    pub output_format: MonitordOutputFormat,
    #[default = 30]
    pub dbus_timeout: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct NetworkdConfig {
    pub enabled: bool,
    /// Use varlink APIs for this collector when the global `[varlink]`
    /// switch is on. Default true: set false to keep this collector on
    /// D-Bus/files while the rest move to varlink.
    #[default = true]
    pub varlink: bool,
    #[default(crate::networkd::NETWORKD_STATE_FILES.into())]
    pub link_state_dir: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct Pid1Config {
    #[default = true]
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct SystemStateConfig {
    #[default = true]
    pub enabled: bool,
    /// Use varlink APIs for this collector when the global `[varlink]`
    /// switch is on. Default true: set false to keep this collector on
    /// D-Bus while the rest move to varlink. Also gates the always-on
    /// systemd version collection, which shares the `Manager.Describe` call.
    #[default = true]
    pub varlink: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct TimersConfig {
    #[default = true]
    pub enabled: bool,
    pub allowlist: HashSet<String>,
    pub blocklist: HashSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct UnitsConfig {
    #[default = true]
    pub enabled: bool,
    /// Use varlink APIs for this collector when the global `[varlink]`
    /// switch is on. Default true: set false to keep this collector on
    /// D-Bus while the rest move to varlink.
    #[default = true]
    pub varlink: bool,
    /// Unit-name patterns for failed counts, keyed by family. Each pattern
    /// matches a full name or contains one `*` matching a non-empty string.
    pub failed_families: BTreeMap<String, String>,
    pub state_stats: bool,
    pub state_stats_allowlist: HashSet<String>,
    pub state_stats_blocklist: HashSet<String>,
    #[default = true]
    pub state_stats_time_in_state: bool,
    /// Host unit names mapped to their health grace period from boot, in seconds.
    pub boot_grace: BTreeMap<String, u64>,
    #[default = true]
    pub ignore_inactive_oneshot_services: bool,
    #[default = true]
    pub unit_files: bool,
    /// Max number of units whose D-Bus work runs concurrently in the per-unit
    /// collection loop. Bounded (rather than unbounded) so a burst of
    /// simultaneous D-Bus calls doesn't itself worsen host-level IPC
    /// contention on hosts where per-call latency is already elevated.
    #[default = 8]
    pub per_unit_concurrency: u64,
    /// Number of slowest units (by per-unit collection duration) to record in
    /// `UnitsCollectionTimings::slowest_units`. Set to 0 to disable.
    #[default = 5]
    pub slowest_units_count: u64,
    /// Varlink path only: the longest, in seconds, a `[services]` entry's
    /// `io.systemd.Unit.List` reply is reused across cycles. Entries are
    /// refetched sooner when the unit changes state or the manager reloads;
    /// this bounds fields that can change without either (e.g. a runtime
    /// `WATCHDOG_USEC=` notify). 0 disables the cache.
    #[default = 300]
    pub service_details_cache_max_age_secs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct MachinesConfig {
    #[default = true]
    pub enabled: bool,
    /// Use varlink APIs inside containers when the global `[varlink]`
    /// switch is on. Default true: set false to keep all container
    /// collection on D-Bus. Container paths additionally require the
    /// matching collector section's own `varlink` toggle. Container varlink
    /// connects from inside the container's PID namespace (see
    /// `crate::varlink::machine_connector`), which needs `CAP_SYS_ADMIN`.
    #[default = true]
    pub varlink: bool,
    pub allowlist: HashSet<String>,
    pub blocklist: HashSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct DBusStatsConfig {
    #[default = true]
    pub enabled: bool,
    #[default = true]
    pub stale_fd_stats: bool,

    pub user_stats: bool,
    pub user_allowlist: HashSet<String>,
    pub user_blocklist: HashSet<String>,

    pub peer_stats: bool,
    pub peer_well_known_names_only: bool,
    pub peer_allowlist: HashSet<String>,
    pub peer_blocklist: HashSet<String>,
    /// Max number of well-known bus names whose owner lookup runs concurrently
    /// when resolving peer names. Bounded (rather than unbounded) for the same
    /// reason as `UnitsConfig::per_unit_concurrency`: a burst of simultaneous
    /// D-Bus calls can itself worsen host-level IPC contention.
    #[default = 8]
    pub peer_name_concurrency: u64,

    pub cgroup_stats: bool,
    pub cgroup_allowlist: HashSet<String>,
    pub cgroup_blocklist: HashSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct BootBlameConfig {
    pub enabled: bool,
    /// Use varlink APIs for this collector when the global `[varlink]`
    /// switch is on. Default true: set false to keep this collector on
    /// D-Bus while the rest move to varlink.
    #[default = true]
    pub varlink: bool,
    #[default = true]
    pub cache_enabled: bool,
    #[default = "/run/monitord"]
    pub cache_dir: String,
    #[default = 5]
    pub num_slowest_units: u64,
    pub allowlist: HashSet<String>,
    pub blocklist: HashSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, SmartDefault)]
pub struct VerifyConfig {
    pub enabled: bool,
    /// Use varlink APIs for this collector when the global `[varlink]`
    /// switch is on. Default true: set false to keep this collector on
    /// D-Bus while the rest move to varlink.
    #[default = true]
    pub varlink: bool,
    pub allowlist: HashSet<String>,
    pub blocklist: HashSet<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VarlinkConfig {
    /// Global varlink master switch. Each varlink-capable collector section
    /// has its own `varlink` opt-out; a collector uses varlink only when
    /// both this and its section toggle are true.
    pub enabled: bool,
    /// Forbid every varlink fallback: any varlink failure is a hard error
    /// instead of falling back to D-Bus (or files for networkd). Off by
    /// default; enable in CI to prove a collector set is varlink-clean
    /// rather than silently D-Bus-served. See `crate::varlink_fallback`
    /// for the shared enforcement point.
    pub no_fallback: bool,
}

/// Output format of a configured report command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportCommandFormat {
    /// One `io.systemd.Metrics.List` JSON object per nonblank line.
    Records,
    /// One finite JSON number, exposed as `<source>.value`.
    Number,
}

/// A trusted executable run directly, with no arguments or shell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportCommand {
    pub path: PathBuf,
    pub format: ReportCommandFormat,
}

/// `[report]` section: serve monitord's own health metrics to
/// `systemd-report` over `io.systemd.Metrics` (see `crate::report`), and
/// collect other systemd-report sources (`/run/systemd/report/*`, systemd
/// v260+) and configured commands (see `crate::report_collector`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReportConfig {
    /// Serve `io.systemd.Metrics` on `/run/systemd/report/io.monitord`
    /// (or a socket-activated fd). Off by default. The binary serves only
    /// in daemon mode; library users start `report::ReportServer` themselves.
    pub enabled: bool,
    /// Collect `io.systemd.Metrics` sources under `/run/systemd/report/`
    /// and run configured commands. Sources already parsed into typed
    /// stats are excluded from socket discovery. Off by default: a single
    /// source may publish thousands of metrics.
    pub collect: bool,
    /// Only collect these socket sources (e.g. `io.systemd.Basic`).
    /// Lowercased by the INI parser, so matched case-insensitively.
    pub allowlist: HashSet<String>,
    /// Never collect these socket sources. Matched case-insensitively.
    pub blocklist: HashSet<String>,
    /// Never collect these metrics, from any source: full metric names
    /// (e.g. `io.systemd.Basic.MachineID`), each also matching every name
    /// under it at a dot boundary (`io.systemd.Basic.SMBIOS` covers
    /// `io.systemd.Basic.SMBIOS.SystemVendor`). Lowercased by the INI
    /// parser, so matched case-insensitively. The example monitord.conf
    /// lists host identifiers here; see the README for why.
    pub metric_blocklist: HashSet<String>,
    /// Explicit command sources, keyed by lowercased interface name. Socket
    /// source filters do not apply to these opt-in sources.
    pub commands: BTreeMap<String, ReportCommand>,
}

/// Config struct
/// Each section represents an ini file section
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Config {
    pub machines: MachinesConfig,
    pub monitord: MonitordConfig,
    pub networkd: NetworkdConfig,
    pub pid1: Pid1Config,
    pub services: HashSet<String>,
    pub system_state: SystemStateConfig,
    pub timers: TimersConfig,
    pub units: UnitsConfig,
    pub dbus_stats: DBusStatsConfig,
    pub boot_blame: BootBlameConfig,
    pub verify: VerifyConfig,
    pub varlink: VarlinkConfig,
    pub report: ReportConfig,
}

impl Config {
    /// Whether collectors gated on the given section toggles may use varlink.
    ///
    /// The global `[varlink]` master switch ANDed with every section toggle
    /// passed. Container paths additionally pass `machines.varlink`, since a
    /// container may run older systemd without the varlink APIs.
    pub fn use_varlink(&self, sections: &[bool]) -> bool {
        self.varlink.enabled && sections.iter().all(|toggle| *toggle)
    }
}

// Match the plain, instance and template names accepted by systemd.
fn valid_unit_name(unit: &str) -> bool {
    const UNIT_TYPES: &[&str] = &[
        "automount",
        "device",
        "mount",
        "path",
        "scope",
        "service",
        "slice",
        "socket",
        "swap",
        "target",
        "timer",
    ];
    let Some((name, suffix)) = unit.rsplit_once('.') else {
        return false;
    };
    unit.len() <= 255
        && !name.is_empty()
        && !name.starts_with('@')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || br":-_.\@".contains(&b))
        && UNIT_TYPES.contains(&suffix)
}

impl TryFrom<Ini> for Config {
    type Error = MonitordConfigError;

    fn try_from(ini_config: Ini) -> Result<Self, MonitordConfigError> {
        let mut config = Config::default();
        let config_map = ini_config.get_map_ref();
        let section_keys = |section: &str| {
            config_map
                .get(section)
                .map(|entries| entries.keys().cloned().collect())
                .unwrap_or_default()
        };

        // [monitord] section
        if let Some(dbus_address) = ini_config.get("monitord", "dbus_address") {
            config.monitord.dbus_address = dbus_address;
        }
        if let Ok(Some(dbus_timeout)) = ini_config.getuint("monitord", "dbus_timeout") {
            config.monitord.dbus_timeout = dbus_timeout;
        }
        config.monitord.daemon = read_config_bool(&ini_config, "monitord", "daemon")?;
        if let Ok(Some(daemon_stats_refresh_secs)) =
            ini_config.getuint("monitord", "daemon_stats_refresh_secs")
        {
            config.monitord.daemon_stats_refresh_secs = daemon_stats_refresh_secs;
        }
        if let Some(key_prefix) = ini_config.get("monitord", "key_prefix") {
            config.monitord.key_prefix = key_prefix;
        }
        let output_format_str = ini_config.get("monitord", "output_format").ok_or_else(|| {
            MonitordConfigError::MissingKey {
                section: "monitord".into(),
                key: "output_format".into(),
            }
        })?;
        config.monitord.output_format = MonitordOutputFormat::from_str(&output_format_str)
            .map_err(|e| MonitordConfigError::InvalidValue {
                section: "monitord".into(),
                key: "output_format".into(),
                reason: e.to_string(),
            })?;

        // [networkd] section
        config.networkd.enabled = read_config_bool(&ini_config, "networkd", "enabled")?;
        if let Some(varlink) = read_config_optional_bool(&ini_config, "networkd", "varlink")? {
            config.networkd.varlink = varlink;
        }
        if let Some(link_state_dir) = ini_config.get("networkd", "link_state_dir") {
            config.networkd.link_state_dir = link_state_dir.into();
        }

        // [pid1] section
        config.pid1.enabled = read_config_bool(&ini_config, "pid1", "enabled")?;

        // [services] section
        config.services = section_keys("services");

        // [system-state] section
        config.system_state.enabled = read_config_bool(&ini_config, "system-state", "enabled")?;
        if let Some(varlink) = read_config_optional_bool(&ini_config, "system-state", "varlink")? {
            config.system_state.varlink = varlink;
        }

        // [timers] section
        config.timers.enabled = read_config_bool(&ini_config, "timers", "enabled")?;
        config.timers.allowlist = section_keys("timers.allowlist");
        config.timers.blocklist = section_keys("timers.blocklist");

        // [units] section
        config.units.enabled = read_config_bool(&ini_config, "units", "enabled")?;
        if let Some(varlink) = read_config_optional_bool(&ini_config, "units", "varlink")? {
            config.units.varlink = varlink;
        }
        if let Some(families) = config_map.get("units.failed_families") {
            for (family, pattern) in families {
                let pattern = pattern.as_deref().unwrap_or("").trim();
                if pattern.is_empty() || pattern.matches('*').count() > 1 {
                    return Err(MonitordConfigError::InvalidValue {
                        section: "units.failed_families".into(),
                        key: family.clone(),
                        reason: "expected a non-empty unit name with at most one '*'".into(),
                    });
                }
                config
                    .units
                    .failed_families
                    .insert(family.clone(), pattern.into());
            }
        }
        config.units.state_stats = read_config_bool(&ini_config, "units", "state_stats")?;
        config.units.state_stats_allowlist = section_keys("units.state_stats.allowlist");
        config.units.state_stats_blocklist = section_keys("units.state_stats.blocklist");
        if let Some(entries) = config_map.get("units.state_stats.boot_grace") {
            for (label, value) in entries {
                let invalid = || MonitordConfigError::InvalidValue {
                    section: "units.state_stats.boot_grace".into(),
                    key: label.clone(),
                    reason: "expected <full unit name>,<non-negative integer seconds>".into(),
                };
                let (unit, seconds) = value
                    .as_deref()
                    .and_then(|value| value.rsplit_once(','))
                    .ok_or_else(invalid)?;
                let unit = unit.trim();
                let seconds = seconds.trim();
                if !valid_unit_name(unit)
                    || seconds.is_empty()
                    || !seconds.bytes().all(|c| c.is_ascii_digit())
                {
                    return Err(invalid());
                }
                let seconds = seconds.parse().map_err(|_| invalid())?;
                config.units.boot_grace.insert(unit.into(), seconds);
            }
        }
        config.units.state_stats_time_in_state =
            read_config_bool(&ini_config, "units", "state_stats_time_in_state")?;
        if let Some(ignore_inactive_oneshot_services) =
            read_config_optional_bool(&ini_config, "units", "ignore_inactive_oneshot_services")?
        {
            config.units.ignore_inactive_oneshot_services = ignore_inactive_oneshot_services;
        }
        if let Some(unit_files) = read_config_optional_bool(&ini_config, "units", "unit_files")? {
            config.units.unit_files = unit_files;
        }
        if let Ok(Some(per_unit_concurrency)) = ini_config.getuint("units", "per_unit_concurrency")
        {
            config.units.per_unit_concurrency = per_unit_concurrency;
        }
        if let Ok(Some(slowest_units_count)) = ini_config.getuint("units", "slowest_units_count") {
            config.units.slowest_units_count = slowest_units_count;
        }
        if let Ok(Some(max_age)) = ini_config.getuint("units", "service_details_cache_max_age_secs")
        {
            config.units.service_details_cache_max_age_secs = max_age;
        }

        // [machines] section
        config.machines.enabled = read_config_bool(&ini_config, "machines", "enabled")?;
        if let Some(varlink) = read_config_optional_bool(&ini_config, "machines", "varlink")? {
            config.machines.varlink = varlink;
        }
        config.machines.allowlist = section_keys("machines.allowlist");
        config.machines.blocklist = section_keys("machines.blocklist");

        // [dbus] section
        config.dbus_stats.enabled = read_config_bool(&ini_config, "dbus", "enabled")?;
        if let Some(stale_fd_stats) =
            read_config_optional_bool(&ini_config, "dbus", "stale_fd_stats")?
        {
            config.dbus_stats.stale_fd_stats = stale_fd_stats;
        }

        config.dbus_stats.user_stats = read_config_bool(&ini_config, "dbus", "user_stats")?;
        config.dbus_stats.user_allowlist = section_keys("dbus.user.allowlist");
        config.dbus_stats.user_blocklist = section_keys("dbus.user.blocklist");

        config.dbus_stats.peer_stats = read_config_bool(&ini_config, "dbus", "peer_stats")?;
        config.dbus_stats.peer_well_known_names_only =
            read_config_bool(&ini_config, "dbus", "peer_well_known_names_only")?;
        config.dbus_stats.peer_allowlist = section_keys("dbus.peer.allowlist");
        config.dbus_stats.peer_blocklist = section_keys("dbus.peer.blocklist");
        if let Ok(Some(peer_name_concurrency)) = ini_config.getuint("dbus", "peer_name_concurrency")
        {
            config.dbus_stats.peer_name_concurrency = peer_name_concurrency;
        }

        config.dbus_stats.cgroup_stats = read_config_bool(&ini_config, "dbus", "cgroup_stats")?;
        config.dbus_stats.cgroup_allowlist = section_keys("dbus.cgroup.allowlist");
        config.dbus_stats.cgroup_blocklist = section_keys("dbus.cgroup.blocklist");

        // [boot] section
        config.boot_blame.enabled = read_config_bool(&ini_config, "boot", "enabled")?;
        if let Some(varlink) = read_config_optional_bool(&ini_config, "boot", "varlink")? {
            config.boot_blame.varlink = varlink;
        }
        if let Some(cache_enabled) =
            read_config_optional_bool(&ini_config, "boot", "cache_enabled")?
        {
            config.boot_blame.cache_enabled = cache_enabled;
        }
        if let Some(cache_dir) = ini_config.get("boot", "cache_dir") {
            config.boot_blame.cache_dir = cache_dir;
        }
        if let Ok(Some(num_slowest_units)) = ini_config.getuint("boot", "num_slowest_units") {
            config.boot_blame.num_slowest_units = num_slowest_units;
        }
        config.boot_blame.allowlist = section_keys("boot.allowlist");
        config.boot_blame.blocklist = section_keys("boot.blocklist");

        // [verify] section
        config.verify.enabled = read_config_bool(&ini_config, "verify", "enabled")?;
        if let Some(varlink) = read_config_optional_bool(&ini_config, "verify", "varlink")? {
            config.verify.varlink = varlink;
        }
        config.verify.allowlist = section_keys("verify.allowlist");
        config.verify.blocklist = section_keys("verify.blocklist");

        // [varlink] section
        config.varlink.enabled = read_config_bool(&ini_config, "varlink", "enabled")?;
        if let Some(no_fallback) = read_config_optional_bool(&ini_config, "varlink", "no_fallback")?
        {
            config.varlink.no_fallback = no_fallback;
        }
        // no_fallback only fires inside varlink code paths, so with the
        // master switch off it is a silent no-op: warn rather than let a
        // fully green all-D-Bus run pose as varlink-clean.
        if config.varlink.no_fallback && !config.varlink.enabled {
            warn!(
                "[varlink] no_fallback=true has no effect while [varlink] enabled=false; \
                 collectors will use D-Bus without a word"
            );
        }

        // [report] section
        if let Some(enabled) = read_config_optional_bool(&ini_config, "report", "enabled")? {
            config.report.enabled = enabled;
        }
        if let Some(collect) = read_config_optional_bool(&ini_config, "report", "collect")? {
            config.report.collect = collect;
        }
        config.report.allowlist = section_keys("report.sources.allowlist");
        config.report.blocklist = section_keys("report.sources.blocklist");
        config.report.metric_blocklist = section_keys("report.metrics.blocklist");
        for (section, format) in [
            ("report.commands", ReportCommandFormat::Records),
            ("report.commands.number", ReportCommandFormat::Number),
        ] {
            if let Some(commands) = config_map.get(section) {
                for (name, value) in commands {
                    let invalid = |reason: &str| MonitordConfigError::InvalidValue {
                        section: section.to_string(),
                        key: name.clone(),
                        reason: reason.to_string(),
                    };
                    if !crate::report_collector::interface_name_is_valid(name) {
                        return Err(invalid("expected a Varlink interface name"));
                    }
                    let path = value
                        .as_deref()
                        .map(PathBuf::from)
                        .filter(|path| path.is_absolute())
                        .ok_or_else(|| invalid("expected an absolute executable path"))?;
                    if config
                        .report
                        .commands
                        .insert(name.clone(), ReportCommand { path, format })
                        .is_some()
                    {
                        return Err(invalid("source appears in both command sections"));
                    }
                }
            }
        }

        for entry in unknown_config_entries(config_map) {
            warn!("Ignoring {entry}; check for a typo'd key or section");
        }

        Ok(config)
    }
}

/// Fixed-key sections and every key monitord reads from each.
///
/// Data sections (`[services]`, `*.allowlist`, `*.blocklist`) take arbitrary
/// entries and are exempt; anything else unknown is warned about so a typo'd
/// key parses loudly instead of silently doing nothing.
const KNOWN_SECTION_KEYS: &[(&str, &[&str])] = &[
    (
        "monitord",
        &[
            "dbus_address",
            "dbus_timeout",
            "daemon",
            "daemon_stats_refresh_secs",
            "key_prefix",
            "output_format",
        ],
    ),
    ("networkd", &["enabled", "varlink", "link_state_dir"]),
    ("pid1", &["enabled"]),
    ("system-state", &["enabled", "varlink"]),
    ("timers", &["enabled"]),
    (
        "units",
        &[
            "enabled",
            "varlink",
            "state_stats",
            "state_stats_time_in_state",
            "ignore_inactive_oneshot_services",
            "unit_files",
            "per_unit_concurrency",
            "slowest_units_count",
            "service_details_cache_max_age_secs",
        ],
    ),
    ("machines", &["enabled", "varlink"]),
    (
        "dbus",
        &[
            "enabled",
            "stale_fd_stats",
            "user_stats",
            "peer_stats",
            "peer_well_known_names_only",
            "peer_name_concurrency",
            "cgroup_stats",
        ],
    ),
    (
        "boot",
        &[
            "enabled",
            "varlink",
            "cache_enabled",
            "cache_dir",
            "num_slowest_units",
        ],
    ),
    ("verify", &["enabled", "varlink"]),
    ("varlink", &["enabled", "no_fallback"]),
    ("report", &["enabled", "collect"]),
];

/// Sections whose entries are data (unit/machine names), not fixed keys.
const DATA_SECTIONS: &[&str] = &[
    "services",
    "timers.allowlist",
    "timers.blocklist",
    "units.failed_families",
    "units.state_stats.allowlist",
    "units.state_stats.blocklist",
    "units.state_stats.boot_grace",
    "machines.allowlist",
    "machines.blocklist",
    "dbus.user.allowlist",
    "dbus.user.blocklist",
    "dbus.peer.allowlist",
    "dbus.peer.blocklist",
    "dbus.cgroup.allowlist",
    "dbus.cgroup.blocklist",
    "boot.allowlist",
    "boot.blocklist",
    "verify.allowlist",
    "verify.blocklist",
    "report.sources.allowlist",
    "report.sources.blocklist",
    "report.metrics.blocklist",
    "report.commands",
    "report.commands.number",
];

/// Unrecognized sections and keys, for warn-on-typo diagnostics.
///
/// Pure (returns messages) so tests can assert on it; the caller logs them.
fn unknown_config_entries(
    config_map: &IndexMap<String, IndexMap<String, Option<String>>>,
) -> Vec<String> {
    let mut unknown = Vec::new();
    for (section, keys) in config_map {
        if DATA_SECTIONS.contains(&section.as_str()) {
            continue;
        }
        match KNOWN_SECTION_KEYS.iter().find(|(name, _)| name == section) {
            None => unknown.push(format!("unknown section [{section}]")),
            Some((_, known_keys)) => {
                for key in keys.keys() {
                    if !known_keys.contains(&key.as_str()) {
                        unknown.push(format!("unknown key '{key}' in [{section}]"));
                    }
                }
            }
        }
    }
    unknown
}

/// Helper function to read "bool" config options
fn read_config_bool(config: &Ini, section: &str, key: &str) -> Result<bool, MonitordConfigError> {
    let option_bool =
        config
            .getbool(section, key)
            .map_err(|err| MonitordConfigError::InvalidValue {
                section: section.into(),
                key: key.into(),
                reason: err,
            })?;
    match option_bool {
        Some(bool_value) => Ok(bool_value),
        None => {
            error!(
                "No value for '{}' in '{}' section ... assuming false",
                key, section
            );
            Ok(false)
        }
    }
}

/// Helper function to read optional bool config options while preserving field defaults
fn read_config_optional_bool(
    config: &Ini,
    section: &str,
    key: &str,
) -> Result<Option<bool>, MonitordConfigError> {
    config
        .getbool(section, key)
        .map_err(|err| MonitordConfigError::InvalidValue {
            section: section.into(),
            key: key.into(),
            reason: err,
        })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    const FULL_CONFIG: &str = r###"
[monitord]
dbus_address = unix:path=/system_bus_socket
dbus_timeout = 2
daemon = true
daemon_stats_refresh_secs = 0
key_prefix = unittest
output_format = json-pretty

[networkd]
enabled = true
varlink = false
link_state_dir = /links

[pid1]
enabled = true

[services]
foo.service
bar.service

[system-state]
enabled = true
varlink = false

[timers]
enabled = true

[timers.allowlist]
foo.timer

[timers.blocklist]
bar.timer

[units]
enabled = true
varlink = false
state_stats = true
state_stats_time_in_state = true
ignore_inactive_oneshot_services = true
unit_files = true
per_unit_concurrency = 16
slowest_units_count = 3
service_details_cache_max_age_secs = 600

[units.failed_families]
Worker = Worker@*.service

[units.state_stats.boot_grace]
Blue = Database@Blue.service,240

[units.state_stats.allowlist]
foo.service

[units.state_stats.blocklist]
bar.service

[machines]
enabled = true
varlink = false

[machines.allowlist]
foo
bar

[machines.blocklist]
foo2

[dbus]
enabled = true
stale_fd_stats = true
user_stats = true
peer_stats = true
peer_well_known_names_only = true
peer_name_concurrency = 12
cgroup_stats = true

[dbus.user.allowlist]
foo
bar

[dbus.user.blocklist]
foo2

[dbus.peer.allowlist]
foo
bar

[dbus.peer.blocklist]
foo2

[dbus.cgroup.allowlist]
foo
bar

[dbus.cgroup.blocklist]
foo2

[boot]
enabled = true
varlink = true
cache_enabled = false
cache_dir = /tmp/monitord-test
num_slowest_units = 10

[boot.allowlist]
foo.service

[boot.blocklist]
bar.service

[verify]
enabled = true
varlink = false

[varlink]
enabled = true
no_fallback = true

[report]
enabled = true
collect = true

[report.sources.allowlist]
io.systemd.Basic

[report.sources.blocklist]
io.systemd.Files

[report.metrics.blocklist]
io.systemd.Basic.MachineID
io.systemd.Basic.SMBIOS
"###;

    const MINIMAL_CONFIG: &str = r###"
[monitord]
output_format = json-flat
"###;

    fn load_ini(contents: &str) -> Ini {
        let mut monitord_config = NamedTempFile::new().expect("Unable to make named tempfile");
        monitord_config
            .write_all(contents.as_bytes())
            .expect("Unable to write out temp config file");
        let mut ini_config = Ini::new();
        ini_config
            .load(monitord_config.path())
            .expect("Unable to load ini config");
        ini_config
    }

    #[test]
    fn test_default_config() {
        assert!(Config::default().units.enabled);
        // Per-section varlink toggles default to following the global switch
        let default_config = Config::default();
        assert!(default_config.units.varlink);
        assert!(default_config.networkd.varlink);
        assert!(default_config.system_state.varlink);
        assert!(default_config.machines.varlink);
        assert!(default_config.boot_blame.varlink);
        assert!(default_config.verify.varlink);
    }

    #[test]
    fn test_minimal_config() {
        let ini_config = load_ini(MINIMAL_CONFIG);

        let expected_config: Config = ini_config.try_into().expect("Failed to parse config");
        // See our one setting is not the default 'json' enum value
        assert_eq!(
            expected_config.monitord.output_format,
            MonitordOutputFormat::JsonFlat,
        );
        // See that one of the enabled bools are false
        assert!(!expected_config.networkd.enabled);
        // Boot cache defaults to enabled when not explicitly configured
        assert!(expected_config.boot_blame.cache_enabled);
        // Oneshot inactive services are ignored by default
        assert!(expected_config.units.ignore_inactive_oneshot_services);
        // The systemd-report server is opt-in
        assert!(!expected_config.report.enabled);
    }

    #[test]
    fn test_boot_grace_values_validate_at_load() {
        for value in [
            "",
            "sshd.service",
            ",2",
            "sshd,2",
            "sshd.sevrice,120",
            "bad?.service,120",
            "@.service,120",
            "unit,name.service,10",
            &format!("{}.service,0", "a".repeat(248)),
            "sshd.service,-1",
            "sshd.service,1.5",
            "sshd.service,+1",
            "sshd.service,18446744073709551616",
            "sshd.service,no",
            "bad unit.service,1",
            "sshd.service,",
        ] {
            let invalid_config = format!(
                r###"
[monitord]
output_format = json

[units.state_stats.boot_grace]
unit = {value}
"###
            );
            let ini_config = load_ini(&invalid_config);
            assert!(
                matches!(
                    Config::try_from(ini_config),
                    Err(MonitordConfigError::InvalidValue { section, .. })
                        if section == "units.state_stats.boot_grace"
                ),
                "{value}"
            );
        }

        let boot_grace_config = r###"
[monitord]
output_format = json

[units.state_stats.boot_grace]
Blue = Database@Blue.service,240
zero = sshd.service,0
comma = unit\x2cname.service,10
swap = dev-zram0.swap,5
"###;
        let ini_config = load_ini(boot_grace_config);
        assert!(unknown_config_entries(ini_config.get_map_ref()).is_empty());
        let config: Config = ini_config.try_into().expect("Failed to parse config");
        assert_eq!(
            config.units.boot_grace,
            BTreeMap::from([
                ("Database@Blue.service".into(), 240),
                ("sshd.service".into(), 0),
                (r"unit\x2cname.service".into(), 10),
                ("dev-zram0.swap".into(), 5),
            ])
        );
    }

    #[test]
    fn test_failed_family_patterns_validate_at_load() {
        for pattern in ["", "worker@**.service", "a*b*c"] {
            let invalid_config = format!(
                r###"
[monitord]
output_format = json

[units.failed_families]
worker = {pattern}
"###
            );
            let ini_config = load_ini(&invalid_config);
            assert!(
                matches!(
                    Config::try_from(ini_config),
                    Err(MonitordConfigError::InvalidValue { section, .. })
                        if section == "units.failed_families"
                ),
                "{pattern}"
            );
        }

        let failed_families_config = r###"
[monitord]
output_format = json

[units.failed_families]
Worker = Worker@*.service
Exact = exact.service
"###;
        let ini_config = load_ini(failed_families_config);
        assert!(unknown_config_entries(ini_config.get_map_ref()).is_empty());
        let config: Config = ini_config.try_into().expect("Failed to parse config");
        assert_eq!(config.units.failed_families["worker"], "Worker@*.service");
        assert_eq!(config.units.failed_families["exact"], "exact.service");
    }

    #[test]
    fn test_failed_family_names_follow_ini_key_rules() {
        // Family labels are opaque keys, not unit or Varlink interface names.
        // The INI parser folds their case but must not reject spaces or '/'.
        let failed_families_config = r###"
[monitord]
output_format = json

[units.failed_families]
Ops group/Worker.1 = Worker@*.service
"###;
        let ini_config = load_ini(failed_families_config);
        let config: Config = ini_config.try_into().expect("Failed to parse config");
        assert_eq!(
            config.units.failed_families,
            BTreeMap::from([("ops group/worker.1".into(), "Worker@*.service".into())])
        );
    }

    #[test]
    fn test_units_ignore_inactive_oneshot_services_override() {
        let units_override_config = r###"
[monitord]
output_format = json

[units]
ignore_inactive_oneshot_services = false
"###;
        let ini_config = load_ini(units_override_config);

        let parsed_config: Config = ini_config.try_into().expect("Failed to parse config");
        assert!(!parsed_config.units.ignore_inactive_oneshot_services);
    }

    #[test]
    fn test_units_per_unit_concurrency_override() {
        let units_override_config = r###"
[monitord]
output_format = json

[units]
per_unit_concurrency = 32
slowest_units_count = 0
service_details_cache_max_age_secs = 0
"###;
        let ini_config = load_ini(units_override_config);

        let parsed_config: Config = ini_config.try_into().expect("Failed to parse config");
        assert_eq!(parsed_config.units.per_unit_concurrency, 32);
        assert_eq!(parsed_config.units.slowest_units_count, 0);
        assert_eq!(parsed_config.units.service_details_cache_max_age_secs, 0);
    }

    #[test]
    fn test_use_varlink_conjunction() {
        // The conjunction is the point of the per-section toggles: every
        // gate must agree, so a global-off with sections on stays off, and
        // any single opt-out disables its collector (plus the container
        // triple-AND through machines.varlink).
        let mut config = Config::default();
        assert!(!config.use_varlink(&[true]));
        config.varlink.enabled = true;
        assert!(config.use_varlink(&[true]));
        assert!(!config.use_varlink(&[false]));
        assert!(!config.use_varlink(&[true, false]));
        assert!(config.use_varlink(&[true, true]));
        config.varlink.enabled = false;
        assert!(!config.use_varlink(&[true, true]));
    }

    #[test]
    fn test_unknown_config_entries() {
        // Typo'd keys and sections parse clean, so they must at least warn:
        // [timers] varlink is the trap (timers follow [units]), and data
        // sections must stay exempt since their entries are unit names.
        let typo_config = r###"
[monitord]
output_format = json

[units]
varlnik = false

[timers]
varlink = false

[services]
foo.service

[bogus]
key = value
"###;
        let ini_config = load_ini(typo_config);

        let unknown = unknown_config_entries(&ini_config.get_map().expect("config map"));
        assert!(unknown.contains(&"unknown key 'varlnik' in [units]".to_string()));
        assert!(unknown.contains(&"unknown key 'varlink' in [timers]".to_string()));
        assert!(unknown.contains(&"unknown section [bogus]".to_string()));
        assert_eq!(unknown.len(), 3);
    }

    #[test]
    fn test_no_fallback_parses_and_defaults_off() {
        // Explicit true parses; absence keeps the derived Default (false),
        // so stock configs without the key behave exactly as before.
        let on = r###"
[monitord]
output_format = json

[varlink]
enabled = true
no_fallback = true
"###;
        let ini = load_ini(on);
        let parsed: Config = ini.try_into().expect("parse");
        assert!(parsed.varlink.no_fallback);

        let off = r###"
[monitord]
output_format = json

[varlink]
enabled = true
"###;
        let ini = load_ini(off);
        let parsed: Config = ini.try_into().expect("parse");
        assert!(!parsed.varlink.no_fallback);
    }

    #[test]
    fn test_per_section_varlink_toggle_defaults_and_override() {
        // Only [units] opts out; every other section keeps the default true,
        // so collectors can move to varlink one at a time.
        let varlink_override_config = r###"
[monitord]
output_format = json

[varlink]
enabled = true

[units]
varlink = false
"###;
        let ini_config = load_ini(varlink_override_config);

        let parsed_config: Config = ini_config.try_into().expect("Failed to parse config");
        assert!(parsed_config.varlink.enabled);
        assert!(!parsed_config.units.varlink);
        assert!(parsed_config.networkd.varlink);
        assert!(parsed_config.system_state.varlink);
        assert!(parsed_config.machines.varlink);
        assert!(parsed_config.boot_blame.varlink);
        assert!(parsed_config.verify.varlink);
    }

    #[test]
    fn test_full_config() {
        let expected_config = Config {
            monitord: MonitordConfig {
                dbus_address: String::from("unix:path=/system_bus_socket"),
                daemon: true,
                daemon_stats_refresh_secs: u64::MIN,
                key_prefix: String::from("unittest"),
                output_format: MonitordOutputFormat::JsonPretty,
                dbus_timeout: 2 as u64,
            },
            networkd: NetworkdConfig {
                enabled: true,
                varlink: false,
                link_state_dir: "/links".into(),
            },
            pid1: Pid1Config { enabled: true },
            services: HashSet::from([String::from("foo.service"), String::from("bar.service")]),
            system_state: SystemStateConfig {
                enabled: true,
                varlink: false,
            },
            timers: TimersConfig {
                enabled: true,
                allowlist: HashSet::from([String::from("foo.timer")]),
                blocklist: HashSet::from([String::from("bar.timer")]),
            },
            units: UnitsConfig {
                enabled: true,
                varlink: false,
                failed_families: BTreeMap::from([("worker".into(), "Worker@*.service".into())]),
                state_stats: true,
                state_stats_allowlist: HashSet::from([String::from("foo.service")]),
                state_stats_blocklist: HashSet::from([String::from("bar.service")]),
                state_stats_time_in_state: true,
                boot_grace: BTreeMap::from([("Database@Blue.service".into(), 240)]),
                ignore_inactive_oneshot_services: true,
                unit_files: true,
                per_unit_concurrency: 16,
                slowest_units_count: 3,
                service_details_cache_max_age_secs: 600,
            },
            machines: MachinesConfig {
                enabled: true,
                varlink: false,
                allowlist: HashSet::from([String::from("foo"), String::from("bar")]),
                blocklist: HashSet::from([String::from("foo2")]),
            },
            dbus_stats: DBusStatsConfig {
                enabled: true,
                stale_fd_stats: true,
                user_stats: true,
                user_allowlist: HashSet::from([String::from("foo"), String::from("bar")]),
                user_blocklist: HashSet::from([String::from("foo2")]),
                peer_stats: true,
                peer_well_known_names_only: true,
                peer_allowlist: HashSet::from([String::from("foo"), String::from("bar")]),
                peer_blocklist: HashSet::from([String::from("foo2")]),
                peer_name_concurrency: 12,
                cgroup_stats: true,
                cgroup_allowlist: HashSet::from([String::from("foo"), String::from("bar")]),
                cgroup_blocklist: HashSet::from([String::from("foo2")]),
            },
            boot_blame: BootBlameConfig {
                enabled: true,
                // Explicit true (the other sections pin false): proves the
                // key is actually read rather than the default shining
                // through.
                varlink: true,
                cache_enabled: false,
                cache_dir: "/tmp/monitord-test".to_string(),
                num_slowest_units: 10,
                allowlist: HashSet::from([String::from("foo.service")]),
                blocklist: HashSet::from([String::from("bar.service")]),
            },
            verify: VerifyConfig {
                enabled: true,
                varlink: false,
                allowlist: HashSet::new(),
                blocklist: HashSet::new(),
            },
            varlink: VarlinkConfig {
                enabled: true,
                no_fallback: true,
            },
            report: ReportConfig {
                enabled: true,
                collect: true,
                allowlist: HashSet::from([String::from("io.systemd.basic")]),
                blocklist: HashSet::from([String::from("io.systemd.files")]),
                metric_blocklist: HashSet::from([
                    String::from("io.systemd.basic.machineid"),
                    String::from("io.systemd.basic.smbios"),
                ]),
                commands: BTreeMap::new(),
            },
        };

        let ini_config = load_ini(FULL_CONFIG);

        // See everything set / overloaded ...
        let actual_config: Config = ini_config.try_into().expect("Failed to parse config");
        assert_eq!(expected_config, actual_config);
    }

    #[test]
    fn test_invalid_config_returns_error() {
        let invalid_config = "[monitord]\ndaemon = notabool\noutput_format = json\n";
        let ini_config = load_ini(invalid_config);

        let result: Result<Config, _> = ini_config.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_report_commands_validate_names_paths_and_duplicates() {
        for text in [
            r###"
[report.commands]
com.example.check = relative/path
"###,
            r###"
[report.commands]
com.example.check
"###,
            r###"
[report.commands]
bad = /bin/true
"###,
            r###"
[report.commands]
com.example.check = /bin/true

[report.commands.number]
COM.EXAMPLE.CHECK = /bin/false
"###,
        ] {
            let invalid_config = format!(
                r###"
[monitord]
output_format = json
{text}
"###
            );
            let ini_config = load_ini(&invalid_config);
            assert!(Config::try_from(ini_config).is_err(), "{text}");
        }

        let commands_config = r###"
[monitord]
output_format = json

[report.commands]
COM.EXAMPLE.Check = /usr/libexec/Record With Spaces

[report.commands.number]
io.monitord = /usr/libexec/Number
"###;
        let ini_config = load_ini(commands_config);
        assert!(unknown_config_entries(ini_config.get_map_ref()).is_empty());
        let config: Config = ini_config.try_into().expect("Failed to parse config");
        assert_eq!(
            config.report.commands["com.example.check"].path,
            PathBuf::from("/usr/libexec/Record With Spaces")
        );
        assert_eq!(
            config.report.commands["com.example.check"].format,
            ReportCommandFormat::Records
        );
        assert_eq!(
            config.report.commands["io.monitord"].format,
            ReportCommandFormat::Number
        );
    }
}
