//! # timers module
//!
//! All timer related logic goes here. This will be hitting timer specific
//! dbus / varlink etc.

use struct_field_names_as_array::FieldNamesAsArray;
use thiserror::Error;
use tracing::error;

#[derive(Error, Debug)]
pub enum MonitordTimerError {
    #[error("Timer D-Bus error: {0}")]
    ZbusError(#[from] zbus::Error),
}

#[derive(
    serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, FieldNamesAsArray, PartialEq,
)]

/// Per-timer unit metrics from the org.freedesktop.systemd1.Timer D-Bus interface.
/// Ref: <https://www.freedesktop.org/software/systemd/man/org.freedesktop.systemd1.html>
pub struct TimerStats {
    /// AccuracySec timer property in microseconds; systemd may coalesce timer firings within this window to save wakeups
    pub accuracy_usec: u64,
    /// Whether FixedRandomDelay= is set; when true, the random delay is stable across reboots for this timer
    pub fixed_random_delay: bool,
    /// Realtime timestamp (usec since epoch) when this timer last triggered its service unit
    pub last_trigger_usec: u64,
    /// Monotonic timestamp (usec since boot) when this timer last triggered its service unit
    pub last_trigger_usec_monotonic: u64,
    /// Monotonic timestamp (usec since boot) when this timer will next elapse
    pub next_elapse_usec_monotonic: u64,
    /// Realtime timestamp (usec since epoch) when this timer will next elapse
    pub next_elapse_usec_realtime: u64,
    /// Whether Persistent= is set; when true, missed timer runs (e.g. during downtime) are triggered on next boot
    pub persistent: bool,
    /// RandomizedDelaySec property in microseconds; a random delay up to this value is added before each trigger
    pub randomized_delay_usec: u64,
    /// Whether RemainAfterElapse= is set; when true, the timer stays loaded after all triggers have elapsed
    pub remain_after_elapse: bool,
    /// Realtime timestamp (usec since epoch) of the most recent state change of the triggered service unit
    pub service_unit_last_state_change_usec: u64,
    /// Monotonic timestamp (usec since boot) of the most recent state change of the triggered service unit
    pub service_unit_last_state_change_usec_monotonic: u64,
}

pub const TIMER_STATS_FIELD_NAMES: &[&str] = &TimerStats::FIELD_NAMES_AS_ARRAY;

pub async fn collect_timer_stats(
    connection: &zbus::Connection,
    unit: &crate::units::ListedUnit,
) -> Result<TimerStats, MonitordTimerError> {
    let manager = zbus_systemd::systemd1::ManagerProxy::builder(connection)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    collect_timer_stats_with_manager(&manager, unit).await
}

async fn timer_property<T: TryFrom<zbus::OwnedVariant>>(
    value: Option<zbus::OwnedVariant>,
    fallback: impl std::future::Future<Output = zbus::Result<T>>,
) -> zbus::Result<T> {
    match value.and_then(|value| value.try_into().ok()) {
        Some(value) => Ok(value),
        None => fallback.await,
    }
}

#[tracing::instrument(name = "collect_timer_stats", level = "debug", skip(manager))]
pub(crate) async fn collect_timer_stats_with_manager(
    manager: &zbus_systemd::systemd1::ManagerProxy<'_>,
    unit: &crate::units::ListedUnit,
) -> Result<TimerStats, MonitordTimerError> {
    let connection = manager.inner().connection();
    let timer = zbus_systemd::systemd1::TimerProxy::builder(connection)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .path(unit.unit_object_path.clone())
        .build()
        .await?;
    let mut values = zbus::fdo::PropertiesProxy::builder(connection)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .destination(timer.inner().destination())
        .path(timer.inner().path())
        .build()
        .await?
        .get_all(timer.inner().interface().as_ref())
        .await
        .unwrap_or_default();
    let service_unit = timer_property(values.remove("Unit"), timer.unit()).await?;
    let mut timer_stats = TimerStats::default();
    if service_unit.is_empty() {
        error!("{}: No service unit name found for timer.", unit.name);
    } else {
        let service_unit_path = manager.get_unit(service_unit).await?;
        let up = zbus_systemd::systemd1::UnitProxy::builder(connection)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .path(service_unit_path)
            .build()
            .await?;
        let (realtime, monotonic) = tokio::join!(
            up.state_change_timestamp(),
            up.state_change_timestamp_monotonic(),
        );
        timer_stats.service_unit_last_state_change_usec = realtime?;
        timer_stats.service_unit_last_state_change_usec_monotonic = monotonic?;
    }

    // GetAll can omit properties or be denied outright. Issue any fallback
    // Gets together, then report errors in property order.
    let (
        accuracy_usec,
        fixed_random_delay,
        last_trigger_usec,
        last_trigger_usec_monotonic,
        persistent,
        next_elapse_usec_monotonic,
        next_elapse_usec_realtime,
        randomized_delay_usec,
        remain_after_elapse,
    ) = tokio::join!(
        timer_property(values.remove("AccuracyUSec"), timer.accuracy_u_sec()),
        timer_property(
            values.remove("FixedRandomDelay"),
            timer.fixed_random_delay()
        ),
        timer_property(values.remove("LastTriggerUSec"), timer.last_trigger_u_sec()),
        timer_property(
            values.remove("LastTriggerUSecMonotonic"),
            timer.last_trigger_u_sec_monotonic()
        ),
        timer_property(values.remove("Persistent"), timer.persistent()),
        timer_property(
            values.remove("NextElapseUSecMonotonic"),
            timer.next_elapse_u_sec_monotonic()
        ),
        timer_property(
            values.remove("NextElapseUSecRealtime"),
            timer.next_elapse_u_sec_realtime()
        ),
        timer_property(
            values.remove("RandomizedDelayUSec"),
            timer.randomized_delay_u_sec()
        ),
        timer_property(
            values.remove("RemainAfterElapse"),
            timer.remain_after_elapse()
        ),
    );

    timer_stats.accuracy_usec = accuracy_usec?;
    timer_stats.fixed_random_delay = fixed_random_delay?;
    timer_stats.last_trigger_usec = last_trigger_usec?;
    timer_stats.last_trigger_usec_monotonic = last_trigger_usec_monotonic?;
    timer_stats.persistent = persistent?;
    timer_stats.next_elapse_usec_monotonic = next_elapse_usec_monotonic?;
    timer_stats.next_elapse_usec_realtime = next_elapse_usec_realtime?;
    timer_stats.randomized_delay_usec = randomized_delay_usec?;
    timer_stats.remain_after_elapse = remain_after_elapse?;

    Ok(timer_stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timer_property_uses_get_for_missing_or_invalid_values() {
        let cached = timer_property::<bool>(Some(false.into()), async { panic!("unexpected Get") });
        assert!(!cached.await.unwrap());
        let invalid = timer_property(Some(0u64.into()), async { Ok(true) });
        assert!(invalid.await.unwrap());
        let missing = timer_property::<u64>(None, async { Err(zbus::Error::IncorrectType) });
        assert!(matches!(missing.await, Err(zbus::Error::IncorrectType)));
    }

    #[test]
    fn test_only_timer_units_are_selected() {
        // Both collection paths pick timers out of a list of every unit, so the
        // match has to be on the suffix. `.contains(".timer")` also matched
        // units that merely mention a timer in their name, which then failed a
        // TimerProxy call and logged an error for a unit that was never a timer.
        let selects = |name: &str| name.ends_with(crate::unit_constants::SYSTEMD_TIMER_SUFFIX);

        assert!(selects("logrotate.timer"));
        assert!(selects("systemd-tmpfiles-clean.timer"));

        assert!(!selects("my.timer.service"));
        assert!(!selects("foo.timers.service"));
        assert!(!selects("timer.target"));
        assert!(!selects("dbus-broker.service"));
    }
}
