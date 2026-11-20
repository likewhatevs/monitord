//! # varlink_unit module
//!
//! Per-unit detail via the `io.systemd.Unit` varlink API on PID 1's socket.
//! `Unit.List` itself exists from systemd v258, but the per-type context
//! sections read here (`varlink-service.c`, `varlink-timer.c`) first appear in
//! **v261**, which is the real minimum. This is what the varlink path uses
//! instead of the per-unit D-Bus property fetches in `units.rs`.
//!
//! `Unit.List` can either stream every unit or answer for one named unit.
//! monitord asks per unit: measured on a test host with 305 units, streaming
//! all of them costs ~92ms and 1.3MB, against ~0.47ms for a single filtered
//! call on a warm connection. Break-even is around 198 units, and monitord
//! wants a handful — the `[services]` list, the tracked timers, and whichever
//! units need a oneshot type check. The collectors that do want every unit
//! (`boot_blame`, `verify`) are served from the metrics stream instead.
//!
//! systemd omits fields that sit at their default rather than sending a zero,
//! so every mapping below has to restate the default the D-Bus property would
//! have returned. Those defaults are asserted in the tests.

use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use tracing::debug;

use crate::timer::TimerStats;
use crate::units::ServiceStats;
use crate::varlink::unit::{ListOutput, Unit};

pub use crate::varlink::manager::MANAGER_SOCKET_PATH;

/// systemd reports "unset" counters as `u64::MAX` over D-Bus (`[not set]` /
/// `infinity` in `systemctl show`) and by omitting the field over varlink.
const UNSET: u64 = u64::MAX;

/// A connection to PID 1's unit API that remembers what it has already asked.
///
/// Built once per collection cycle. The cache matters because the same unit can
/// be wanted by more than one caller in a cycle — a `.service` can be both in
/// `[services]` and the target of a tracked timer — and a miss costs a round
/// trip to PID 1, which serves varlink requests one at a time.
pub struct UnitLookup {
    connection: zlink::tokio::unix::Connection,
    cache: HashMap<String, Option<ListOutput>>,
    fetches: u64,
    fetch_total: Duration,
    fetch_max: Duration,
}

impl UnitLookup {
    pub async fn connect(
        endpoint: &crate::varlink::endpoint::VarlinkEndpoint,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            connection: endpoint.connect().await?,
            cache: HashMap::new(),
            fetches: 0,
            fetch_total: Duration::ZERO,
            fetch_max: Duration::ZERO,
        })
    }

    /// Look a unit up, returning `Ok(None)` if systemd does not know it, or
    /// knows it only as masked or failed to load (`UnitMasked`/`UnitError`),
    /// matching D-Bus `ListUnits`, which has no service data for those either.
    ///
    /// A transport or protocol failure is an error rather than `None`, so the
    /// caller can fall back to D-Bus for the whole phase. Collapsing the two
    /// would leave service stats silently empty on a broken socket while
    /// reporting success.
    ///
    /// A unit that is genuinely absent is cached as absent: the answer will not
    /// change within a cycle, and re-asking would cost another round trip.
    pub async fn get(&mut self, name: &str) -> anyhow::Result<Option<&ListOutput>> {
        if !self.cache.contains_key(name) {
            let start = Instant::now();
            let reply = self.connection.list(Some(name)).await;
            let elapsed = start.elapsed();
            self.fetches += 1;
            self.fetch_total += elapsed;
            self.fetch_max = self.fetch_max.max(elapsed);
            let fetched = match reply? {
                Ok(output) => Some(output),
                Err(err) => {
                    debug!("No unit {} over varlink: {}", name, err);
                    None
                }
            };
            self.cache.insert(name.to_string(), fetched);
        }
        Ok(self.cache.get(name).and_then(|entry| entry.as_ref()))
    }

    /// Answer later `get`s for `name` with a reply kept from an earlier cycle,
    /// so other passes this cycle (oneshot types, a timer's triggered unit)
    /// reuse it rather than asking PID 1 again. Never replaces a fresher reply.
    pub fn seed(&mut self, name: &str, output: ListOutput) {
        self.cache.entry(name.to_string()).or_insert(Some(output));
    }

    /// Number of `Unit.List` calls made to PID 1 so far, for collection
    /// timings. Seeded replies are not counted.
    pub fn fetches(&self) -> u64 {
        self.fetches
    }

    /// Total time spent waiting on `Unit.List` calls so far.
    pub fn fetch_total(&self) -> Duration {
        self.fetch_total
    }

    /// The slowest single `Unit.List` call so far.
    pub fn fetch_max(&self) -> Duration {
        self.fetch_max
    }
}

/// Whether a unit is a oneshot service.
///
/// The varlink equivalent of the D-Bus path's `Service.Type` check in
/// `units::is_oneshot_service_unit`.
pub fn is_oneshot(output: &ListOutput) -> bool {
    output
        .context
        .as_ref()
        .and_then(|context| context.service.as_ref())
        .and_then(|service| service.r#type.as_deref())
        == Some("oneshot")
}

/// Map a `Unit.List` reply onto `ServiceStats`.
///
/// The seven cgroup-derived fields come from `cgroup` (read from cgroupfs
/// via `crate::cgroup`, #221) rather than the reply: `Unit.List`'s
/// `runtime.CGroup` only carries values when the matching accounting option
/// is on, while the files are always there when the controller is enabled.
/// A cgroup field with no filesystem data falls back to the reply value,
/// defaulting to UNSET when the reply omits it too.
pub fn map_service_stats(output: &ListOutput, cgroup: &crate::cgroup::CgroupStats) -> ServiceStats {
    let empty_cgroup = Default::default();
    let reply = output
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.cgroup.as_ref())
        .unwrap_or(&empty_cgroup);
    let or_reply = |fs: Option<u64>, reply| fs.or(reply).unwrap_or(UNSET);
    let mut stats = ServiceStats {
        cpuusage_nsec: or_reply(cgroup.cpu_usage_nsec, reply.cpu_usage_nsec),
        ioread_bytes: or_reply(cgroup.io_read_bytes, reply.io_read_bytes),
        ioread_operations: or_reply(cgroup.io_read_operations, reply.io_read_operations),
        memory_available: or_reply(cgroup.memory_available, reply.memory_available),
        memory_current: or_reply(cgroup.memory_current, reply.memory_current),
        tasks_current: or_reply(cgroup.tasks_current, reply.tasks_current),
        processes: cgroup.processes,
        // TimeoutCleanUSec is under Exec and defaults to infinity on D-Bus.
        timeout_clean_usec: output
            .context
            .as_ref()
            .and_then(|context| context.exec.as_ref())
            .and_then(|exec| exec.timeout_clean_usec)
            .unwrap_or(UNSET),
        ..ServiceStats::default()
    };
    if let Some(service) = output
        .context
        .as_ref()
        .and_then(|context| context.service.as_ref())
    {
        stats.restart_usec = service.restart_usec.unwrap_or_default();
        stats.watchdog_usec = service.watchdog_usec.unwrap_or_default();
    }
    if let Some(runtime) = &output.runtime {
        let realtime = |ts: Option<crate::varlink::unit::Timestamp>| {
            ts.and_then(|ts| ts.realtime).unwrap_or_default()
        };
        stats.active_enter_timestamp = realtime(runtime.active_enter_timestamp);
        stats.active_exit_timestamp = realtime(runtime.active_exit_timestamp);
        stats.inactive_exit_timestamp = realtime(runtime.inactive_exit_timestamp);
        stats.state_change_timestamp = realtime(runtime.state_change_timestamp);
        if let Some(service) = &runtime.service {
            stats.nrestarts = service.n_restarts.unwrap_or_default();
            stats.status_errno = service.status_errno.unwrap_or_default();
        }
    }
    stats
}

/// Whether `map_service_stats` would take any cgroup counter from the reply
/// because cgroupfs had no value for it.
///
/// Those reply counters are a snapshot of the moment PID 1 answered, so a
/// reply that needs them must not be reused on a later cycle: it would report
/// the same memory and CPU forever while the unit holds its state.
///
/// The common case is a unit with no cgroup (e.g. an exited oneshot with
/// `RemainAfterExit=yes`): PID 1 still answers `MemoryAvailable`, recomputed
/// live from its ancestors and the host, so such units are asked every cycle.
pub fn uses_reply_cgroup_fallback(
    output: &ListOutput,
    cgroup: &crate::cgroup::CgroupStats,
) -> bool {
    let Some(reply) = output
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.cgroup.as_ref())
    else {
        return false;
    };
    [
        (cgroup.cpu_usage_nsec, reply.cpu_usage_nsec),
        (cgroup.io_read_bytes, reply.io_read_bytes),
        (cgroup.io_read_operations, reply.io_read_operations),
        (cgroup.memory_available, reply.memory_available),
        (cgroup.memory_current, reply.memory_current),
        (cgroup.tasks_current, reply.tasks_current),
    ]
    .iter()
    .any(|(fs, reply)| fs.is_none() && reply.is_some())
}

/// The unit a timer triggers, e.g. "logrotate.service" for "logrotate.timer".
pub fn timer_triggered_unit(output: &ListOutput) -> Option<&str> {
    output
        .context
        .as_ref()
        .and_then(|context| context.timer.as_ref())
        .and_then(|timer| timer.unit.as_deref())
}

/// Map a `Unit.List` reply onto `TimerStats`.
///
/// `triggered` is the reply for the unit this timer starts, looked up
/// separately because its state change timestamps are properties of that unit
/// rather than of the timer. `None` when it could not be resolved, which
/// leaves those two fields at 0 — the same as the D-Bus path, which reports 0
/// when the timer names no unit.
pub fn map_timer_stats(output: &ListOutput, triggered: Option<&ListOutput>) -> TimerStats {
    let mut stats = TimerStats::default();
    if let Some(timer) = output
        .context
        .as_ref()
        .and_then(|context| context.timer.as_ref())
    {
        stats.accuracy_usec = timer.accuracy_usec.unwrap_or_default();
        stats.fixed_random_delay = timer.fixed_random_delay.unwrap_or_default();
        stats.persistent = timer.persistent.unwrap_or_default();
        stats.randomized_delay_usec = timer.randomized_delay_usec.unwrap_or_default();
        stats.remain_after_elapse = timer.remain_after_elapse.unwrap_or_default();
    }
    if let Some(timer) = output
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.timer.as_ref())
    {
        stats.next_elapse_usec_monotonic = timer.next_elapse_usec_monotonic.unwrap_or_default();
        stats.next_elapse_usec_realtime = timer.next_elapse_usec_realtime.unwrap_or_default();
        if let Some(timestamp) = timer.last_trigger_usec {
            stats.last_trigger_usec = timestamp.realtime.unwrap_or_default();
            stats.last_trigger_usec_monotonic = timestamp.monotonic.unwrap_or_default();
        }
    }
    if let Some(timestamp) = triggered
        .and_then(|unit| unit.runtime.as_ref())
        .and_then(|runtime| runtime.state_change_timestamp)
    {
        stats.service_unit_last_state_change_usec = timestamp.realtime.unwrap_or_default();
        stats.service_unit_last_state_change_usec_monotonic =
            timestamp.monotonic.unwrap_or_default();
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn reply(value: Value) -> ListOutput {
        serde_json::from_value(value).expect("valid Unit.List reply")
    }

    #[test]
    fn test_uses_reply_cgroup_fallback() {
        // (reply key, matching CgroupStats setter) for every counter
        // map_service_stats can take from the reply.
        type Setter = fn(&mut crate::cgroup::CgroupStats);
        let counters: [(&str, Setter); 6] = [
            ("CPUUsageNSec", |c| c.cpu_usage_nsec = Some(1)),
            ("IOReadBytes", |c| c.io_read_bytes = Some(1)),
            ("IOReadOperations", |c| c.io_read_operations = Some(1)),
            ("MemoryAvailable", |c| c.memory_available = Some(1)),
            ("MemoryCurrent", |c| c.memory_current = Some(1)),
            ("TasksCurrent", |c| c.tasks_current = Some(1)),
        ];
        for (key, set) in counters {
            let reply = reply(json!({
                "runtime": { "CGroup": { "Path": "/system.slice/a.service", key: 7 } }
            }));
            let unread = crate::cgroup::CgroupStats::default();
            let mut read = crate::cgroup::CgroupStats::default();
            set(&mut read);
            // cgroupfs had nothing but the reply did: a snapshot, not cacheable.
            assert!(uses_reply_cgroup_fallback(&reply, &unread), "{key}");
            // cgroupfs answered: nothing taken from the reply.
            assert!(!uses_reply_cgroup_fallback(&reply, &read), "{key}");
        }
        // Neither side had a value, or no cgroup section at all.
        let bare = reply(json!({
            "runtime": { "CGroup": { "Path": "/system.slice/a.service" } }
        }));
        let unread = crate::cgroup::CgroupStats::default();
        assert!(!uses_reply_cgroup_fallback(&bare, &unread));
        assert!(!uses_reply_cgroup_fallback(&reply(json!({})), &unread));
    }

    #[test]
    fn test_is_oneshot() {
        let service = |kind: &str| reply(json!({"context": {"Service": {"Type": kind}}}));
        assert!(is_oneshot(&service("oneshot")));
        assert!(!is_oneshot(&service("notify-reload")));
        // A unit with no service context at all is not a service, let alone a
        // oneshot one — the D-Bus path treats a failed lookup the same way.
        assert!(!is_oneshot(&reply(json!({}))));
    }

    #[test]
    fn test_map_service_stats_from_a_populated_reply() {
        let stats = map_service_stats(
            &reply(json!({
                "context": {
                    "Service": {"Type": "notify-reload", "RestartUSec": 100_000, "WatchdogUSec": null},
                    "Exec": {"TimeoutCleanUSec": 30_000_000}
                },
                "runtime": {
                    "StateChangeTimestamp": {
                        "realtime": 1_789_701_442_296_989_u64,
                        "monotonic": 3_774_344_633_u64
                    },
                    "ActiveEnterTimestamp": {
                        "realtime": 1_789_701_442_296_989_u64,
                        "monotonic": 3_774_344_633_u64
                    },
                    "InactiveExitTimestamp": {
                        "realtime": 1_789_701_442_287_084_u64,
                        "monotonic": 3_774_334_729_u64
                    },
                    "ActiveExitTimestamp": {
                        "realtime": 1_789_701_442_280_000_u64,
                        "monotonic": 3_774_327_645_u64
                    },
                    "CGroup": {
                        "Path": "/system.slice/dbus-broker.service",
                        "CPUUsageNSec": 86_690_000,
                        "MemoryCurrent": 3_457_024,
                        "MemoryAvailable": 7_619_899_392_u64,
                        "TasksCurrent": 2
                    },
                    "Service": {"StatusErrno": 13, "NRestarts": 2}
                }
            })),
            // cgroupfs has fresher data than the reply for these three; the
            // rest fall back to the reply values above.
            &crate::cgroup::CgroupStats {
                cpu_usage_nsec: Some(90_000_000),
                memory_current: Some(4_000_000),
                tasks_current: Some(3),
                processes: 3,
                ..Default::default()
            },
        );

        assert_eq!(stats.state_change_timestamp, 1_789_701_442_296_989);
        assert_eq!(stats.active_enter_timestamp, 1_789_701_442_296_989);
        assert_eq!(stats.inactive_exit_timestamp, 1_789_701_442_287_084);
        assert_eq!(stats.status_errno, 13);
        assert_eq!(stats.nrestarts, 2);
        // cgroupfs wins where it has data…
        assert_eq!(stats.cpuusage_nsec, 90_000_000);
        assert_eq!(stats.memory_current, 4_000_000);
        assert_eq!(stats.tasks_current, 3);
        assert_eq!(stats.processes, 3);
        // …and the reply covers the rest.
        assert_eq!(stats.memory_available, 7_619_899_392);
        assert_eq!(stats.restart_usec, 100_000);
        // Real, and emitted once a unit has actually left the active state.
        assert_eq!(stats.active_exit_timestamp, 1_789_701_442_280_000);
        // Read from context.Exec rather than context.Service.
        assert_eq!(stats.timeout_clean_usec, 30_000_000);
        // Omitted by systemd, so the D-Bus defaults have to be restated here:
        // IO accounting off reads as u64::MAX, WatchdogUSec as 0.
        assert_eq!(stats.ioread_bytes, u64::MAX);
        assert_eq!(stats.ioread_operations, u64::MAX);
        assert_eq!(stats.watchdog_usec, 0);
    }

    fn timer_output() -> ListOutput {
        // Shaped from a real systemd-tmpfiles-clean.timer reply.
        reply(json!({
            "context": {"Timer": {
                "Unit": "systemd-tmpfiles-clean.service",
                "AccuracyUSec": 60_000_000,
                "FixedRandomDelay": false,
                "Persistent": false,
                "RemainAfterElapse": true
            }},
            "runtime": {"Timer": {
                "NextElapseUSecRealtime": 0,
                "NextElapseUSecMonotonic": 91_091_400_515_u64,
                "LastTriggerUSec": {
                    "realtime": 1_789_702_359_355_506_u64,
                    "monotonic": 4_691_399_604_u64
                }
            }}
        }))
    }

    #[test]
    fn test_map_timer_stats() {
        let triggered = reply(json!({
            "runtime": {"StateChangeTimestamp": {
                "realtime": 1_789_702_359_400_000_u64,
                "monotonic": 4_691_444_098_u64
            }}
        }));
        let stats = map_timer_stats(&timer_output(), Some(&triggered));

        assert_eq!(stats.accuracy_usec, 60_000_000);
        assert_eq!(stats.last_trigger_usec, 1_789_702_359_355_506);
        assert_eq!(stats.last_trigger_usec_monotonic, 4_691_399_604);
        assert_eq!(stats.next_elapse_usec_monotonic, 91_091_400_515);
        // A monotonic-only timer reports 0 here, as the D-Bus property does.
        assert_eq!(stats.next_elapse_usec_realtime, 0);
        assert!(stats.remain_after_elapse);
        assert!(!stats.persistent);
        // Omitted by systemd when unset, and 0 over D-Bus.
        assert_eq!(stats.randomized_delay_usec, 0);
        // Comes from the triggered unit, not the timer.
        assert_eq!(
            stats.service_unit_last_state_change_usec,
            1_789_702_359_400_000
        );
        assert_eq!(
            stats.service_unit_last_state_change_usec_monotonic,
            4_691_444_098
        );
    }

    #[test]
    fn test_map_timer_stats_without_the_triggered_unit() {
        // The D-Bus path reports 0 for both when the timer names no unit, so an
        // unresolvable trigger target must not invent a timestamp.
        let stats = map_timer_stats(&timer_output(), None);
        assert_eq!(stats.service_unit_last_state_change_usec, 0);
        assert_eq!(stats.service_unit_last_state_change_usec_monotonic, 0);
        assert_eq!(stats.accuracy_usec, 60_000_000);
    }

    #[test]
    fn test_timer_triggered_unit() {
        assert_eq!(
            timer_triggered_unit(&timer_output()),
            Some("systemd-tmpfiles-clean.service")
        );
        assert_eq!(timer_triggered_unit(&reply(json!({}))), None);
    }

    #[test]
    fn test_map_service_stats_from_an_empty_reply() {
        // Everything absent must land on the D-Bus defaults rather than zeroing
        // the unset sentinels. A service with accounting off reports [not set]
        // over D-Bus, so reporting 0 bytes of memory would be a fabrication.
        let stats = map_service_stats(&reply(json!({})), &crate::cgroup::CgroupStats::default());
        assert_eq!(stats.ioread_bytes, u64::MAX);
        assert_eq!(stats.ioread_operations, u64::MAX);
        assert_eq!(stats.timeout_clean_usec, u64::MAX);
        assert_eq!(stats.cpuusage_nsec, u64::MAX);
        assert_eq!(stats.memory_current, u64::MAX);
        assert_eq!(stats.memory_available, u64::MAX);
        assert_eq!(stats.tasks_current, u64::MAX);
        // These two genuinely default to zero over D-Bus.
        assert_eq!(stats.watchdog_usec, 0);
        assert_eq!(stats.active_enter_timestamp, 0);
    }

    #[test]
    fn test_map_service_stats_cgroupfs_only_no_reply() {
        // A reply with no CGroup section (accounting off, pre-v261, or an
        // inactive unit) still reports everything cgroupfs could read.
        let stats = map_service_stats(
            &reply(json!({})),
            &crate::cgroup::CgroupStats {
                cpu_usage_nsec: Some(1_000),
                memory_current: Some(2_000),
                memory_available: Some(3_000),
                tasks_current: Some(1),
                processes: 1,
                io_read_bytes: Some(0),
                io_read_operations: Some(0),
            },
        );
        assert_eq!(stats.cpuusage_nsec, 1_000);
        assert_eq!(stats.memory_current, 2_000);
        assert_eq!(stats.memory_available, 3_000);
        assert_eq!(stats.tasks_current, 1);
        assert_eq!(stats.processes, 1);
        assert_eq!(stats.ioread_bytes, 0);
        assert_eq!(stats.ioread_operations, 0);
    }
}
