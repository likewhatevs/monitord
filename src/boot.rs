//! # boot module
//!
//! Collects boot blame metrics showing the slowest units at boot.
//! Similar to `systemd-analyze blame` but stores N slowest units.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::num::TryFromIntError;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::RwLock;
use tracing::debug;
use zbus::ObjectPath;
use zbus_systemd::systemd1::{ManagerProxy, UnitProxy};

use crate::config::Config;
use crate::MachineStats;

/// Boot blame statistics: maps unit name to activation time in seconds
pub type BootBlameStats = HashMap<String, f64>;

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const BOOT_BLAME_CACHE_SUFFIX: &str = "boot_blame.bin";

type BootCacheResult<T> = std::result::Result<T, BootCacheError>;

#[derive(Debug, thiserror::Error)]
enum BootCacheError {
    #[error("boot cache I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("boot id from {BOOT_ID_PATH} was empty")]
    EmptyBootId,
    #[error("boot cache payload decode error: {0}")]
    InvalidPayload(&'static str),
    #[error("boot cache UTF-8 decode error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("boot cache integer conversion error: {0}")]
    IntConversion(#[from] TryFromIntError),
}

fn cache_file_path(cache_dir: &Path, boot_id: &str) -> PathBuf {
    cache_dir.join(format!("{boot_id}.{BOOT_BLAME_CACHE_SUFFIX}"))
}

async fn get_boot_id() -> BootCacheResult<String> {
    let boot_id = tokio::fs::read_to_string(BOOT_ID_PATH).await?;
    let boot_id = boot_id.trim().to_string();
    if boot_id.is_empty() {
        return Err(BootCacheError::EmptyBootId);
    }
    Ok(boot_id)
}

fn encode_cached_boot_blame(
    stats: &BootBlameStats,
    transport: crate::CollectorTransport,
) -> BootCacheResult<Vec<u8>> {
    let mut out = Vec::new();
    let entry_count = u32::try_from(stats.len())?;
    out.extend_from_slice(&entry_count.to_le_bytes());

    for (unit_name, activation_time) in stats {
        let unit_name_bytes = unit_name.as_bytes();
        let unit_name_len = u32::try_from(unit_name_bytes.len())?;
        out.extend_from_slice(&unit_name_len.to_le_bytes());
        out.extend_from_slice(unit_name_bytes);
        out.extend_from_slice(&activation_time.to_le_bytes());
    }

    out.push(transport as u8);
    Ok(out)
}

/// Cached boot blame payload plus the transport that produced it.
///
/// The transport byte is appended after the entries by current writers.
/// `None` means a legacy file written before transport tracking existed —
/// the caller treats that as a miss and re-collects, so a legacy hit can
/// never emit a gauge claiming a transport that was never recorded.
struct DecodedBootBlame {
    stats: BootBlameStats,
    transport: Option<crate::CollectorTransport>,
}

fn decode_cached_boot_blame(mut content: &[u8]) -> BootCacheResult<DecodedBootBlame> {
    fn read_number<const N: usize>(content: &mut &[u8]) -> BootCacheResult<[u8; N]> {
        let (number, rest) = content
            .split_first_chunk()
            .ok_or(BootCacheError::InvalidPayload("unexpected end of payload"))?;
        *content = rest;
        Ok(*number)
    }

    let entry_count = u32::from_le_bytes(read_number(&mut content)?);
    let mut stats = BootBlameStats::new();
    for _ in 0..entry_count {
        let name_len = u32::from_le_bytes(read_number(&mut content)?) as usize;
        let name = content
            .split_off(..name_len)
            .ok_or(BootCacheError::InvalidPayload("invalid unit name length"))?;
        let activation_time = f64::from_le_bytes(read_number(&mut content)?);
        stats.insert(String::from_utf8(name.to_vec())?, activation_time);
    }

    let transport = match content {
        [] => None,
        [0] => Some(crate::CollectorTransport::Dbus),
        [1] => Some(crate::CollectorTransport::Varlink),
        _ => return Err(BootCacheError::InvalidPayload("trailing bytes in payload")),
    };
    Ok(DecodedBootBlame { stats, transport })
}

async fn read_cached_boot_blame_from_dir(
    cache_dir: &Path,
    boot_id: &str,
) -> BootCacheResult<Option<DecodedBootBlame>> {
    let cache_path = cache_file_path(cache_dir, boot_id);
    let content = match tokio::fs::read(&cache_path).await {
        Ok(content) => content,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    Ok(Some(decode_cached_boot_blame(&content)?))
}

async fn write_cached_boot_blame_to_dir(
    cache_dir: &Path,
    boot_id: &str,
    stats: &BootBlameStats,
    transport: crate::CollectorTransport,
) -> BootCacheResult<()> {
    tokio::fs::create_dir_all(cache_dir).await?;
    let cache_path = cache_file_path(cache_dir, boot_id);
    let encoded = encode_cached_boot_blame(stats, transport)?;
    tokio::fs::write(cache_path, encoded).await?;
    Ok(())
}

/// Calculate the activation time for a unit
/// Returns the time in seconds from InactiveExitTimestamp to ActiveEnterTimestamp
async fn get_unit_activation_time(
    connection: &zbus::Connection,
    unit_path: &ObjectPath<'_>,
) -> Result<f64> {
    let unit_proxy = UnitProxy::builder(connection)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .path(unit_path)
        .build()
        .await?;

    let inactive_exit = unit_proxy.inactive_exit_timestamp().await?;
    let active_enter = unit_proxy.active_enter_timestamp().await?;

    // If either timestamp is 0, the unit hasn't been activated or the timing is invalid
    if inactive_exit == 0 || active_enter == 0 {
        return Ok(0.0);
    }

    // Calculate activation time in seconds (timestamps are in microseconds)
    let activation_time_usec = active_enter.saturating_sub(inactive_exit);
    let activation_time_sec = activation_time_usec as f64 / 1_000_000.0;

    Ok(activation_time_sec)
}

/// Collect boot blame over D-Bus: one ListUnits plus two property reads
/// per unit on the system.
async fn collect_boot_blame_dbus(
    config: &Config,
    connection: &zbus::Connection,
) -> Result<BootBlameStats> {
    let systemd_proxy = ManagerProxy::builder(connection)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    let units = systemd_proxy.list_units().await?;

    let mut unit_times: Vec<(String, f64)> = Vec::new();

    // Collect activation times for all units
    for unit_info in units {
        let unit_name = unit_info.0;
        let unit_path = unit_info.6;

        // Apply blocklist: skip units explicitly excluded
        if config.boot_blame.blocklist.contains(&unit_name) {
            debug!("Skipping boot blame for {} due to blocklist", &unit_name);
            continue;
        }
        // Apply allowlist: if non-empty, only include listed units
        if !config.boot_blame.allowlist.is_empty()
            && !config.boot_blame.allowlist.contains(&unit_name)
        {
            continue;
        }

        match get_unit_activation_time(connection, &unit_path).await {
            Ok(time) if time > 0.0 => {
                unit_times.push((unit_name, time));
            }
            Ok(_) => {
                // Unit has no activation time (0.0), skip it
            }
            Err(e) => {
                debug!("Failed to get activation time for {}: {}", unit_name, e);
            }
        }
    }

    // Sort by activation time in descending order (slowest first)
    unit_times.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Take only the N slowest units
    let num_slowest = config.boot_blame.num_slowest_units as usize;
    unit_times.truncate(num_slowest);

    // Convert to HashMap
    Ok(unit_times.into_iter().collect())
}

/// Update boot blame statistics with the N slowest units at boot.
///
/// Takes the shared D-Bus cell rather than a connection: cache hits and the
/// varlink path return without ever connecting, so a bus-less host only
/// pays for D-Bus when it actually collects over D-Bus.
pub(crate) async fn update_boot_blame_stats(
    config: Arc<Config>,
    dbus: crate::DbusCell,
    dbus_timeout: u64,
    machine_stats: Arc<RwLock<MachineStats>>,
    no_fallback: bool,
) -> Result<()> {
    debug!("Starting boot blame stats collection");

    let mut maybe_boot_id = None;
    if config.boot_blame.cache_enabled {
        // In-memory hit: the collecting run already recorded which transport
        // produced these stats, so the gauge is intact — keep it.
        let cached_stats = machine_stats.read().await.boot_blame.clone();
        if cached_stats.is_some() {
            debug!("Using in-memory cached boot blame stats");
            return Ok(());
        }

        let cache_dir = Path::new(&config.boot_blame.cache_dir);
        match get_boot_id().await {
            Ok(boot_id) => {
                match read_cached_boot_blame_from_dir(cache_dir, &boot_id).await {
                    Ok(Some(cached)) => {
                        let cache_path = cache_file_path(cache_dir, &boot_id);
                        debug!(
                            "Using cached boot blame stats from {}",
                            cache_path.display()
                        );
                        let mut stats = machine_stats.write().await;
                        stats.boot_blame = Some(cached.stats);
                        match cached.transport {
                            Some(transport) => {
                                // Replay the transport that produced the
                                // cached entry so the gauge stays stable
                                // across runs instead of going absent.
                                stats.varlink_usage.boot_blame = Some(transport);
                            }
                            None => {
                                // Legacy file from before transport tracking:
                                // re-collect below so the gauge is honest
                                // rather than absent or guessed.
                                debug!(
                                    "Boot blame cache predates transport tracking, re-collecting"
                                );
                                drop(stats);
                                maybe_boot_id = Some(boot_id);
                                return collect_and_cache(
                                    &config,
                                    &dbus,
                                    dbus_timeout,
                                    no_fallback,
                                    machine_stats,
                                    maybe_boot_id,
                                )
                                .await;
                            }
                        }
                        return Ok(());
                    }
                    Ok(None) => {
                        debug!("No cached boot blame stats found for boot id {}", boot_id);
                    }
                    Err(err) => {
                        debug!(
                            "Failed to load boot blame cache for boot id {}: {}",
                            boot_id, err
                        );
                    }
                }
                maybe_boot_id = Some(boot_id);
            }
            Err(err) => {
                debug!("Failed to retrieve boot id for boot blame cache: {}", err);
            }
        }
    }

    collect_and_cache(
        &config,
        &dbus,
        dbus_timeout,
        no_fallback,
        machine_stats,
        maybe_boot_id,
    )
    .await
}

/// Collect boot blame over whichever transport applies, record it, and write
/// the disk cache (stamping which transport produced the entry so cache hits
/// replay an honest gauge instead of going absent).
async fn collect_and_cache(
    config: &Arc<Config>,
    dbus: &crate::DbusCell,
    dbus_timeout: u64,
    no_fallback: bool,
    machine_stats: Arc<RwLock<MachineStats>>,
    maybe_boot_id: Option<String>,
) -> Result<()> {
    let use_varlink = config.use_varlink(&[config.boot_blame.varlink]);
    let (boot_blame_stats, transport) = if use_varlink {
        match crate::varlink_boot::get_boot_blame_stats(
            crate::varlink_boot::METRICS_SOCKET_PATH,
            &config.boot_blame,
        )
        .await
        {
            Ok(stats) => (stats, crate::CollectorTransport::Varlink),
            Err(err) => {
                // Plain `?`: NoFallbackError already renders the full
                // explanation via Display; `{:?}` would dump the struct.
                crate::varlink_fallback::report_varlink_failure(
                    no_fallback,
                    "boot blame",
                    "D-Bus",
                    err,
                )?;
                let connection = crate::dbus_connection(dbus, dbus_timeout)
                    .await
                    .map_err(|e| anyhow!("D-Bus connection error: {:?}", e))?;
                (
                    collect_boot_blame_dbus(config, &connection).await?,
                    crate::CollectorTransport::Dbus,
                )
            }
        }
    } else {
        let connection = crate::dbus_connection(dbus, dbus_timeout)
            .await
            .map_err(|e| anyhow!("D-Bus connection error: {:?}", e))?;
        (
            collect_boot_blame_dbus(config, &connection).await?,
            crate::CollectorTransport::Dbus,
        )
    };

    debug!("Collected {} boot blame stats", boot_blame_stats.len());

    // Update machine stats
    let mut stats = machine_stats.write().await;
    stats.boot_blame = Some(boot_blame_stats);
    stats.varlink_usage.boot_blame = Some(transport);
    if config.boot_blame.cache_enabled {
        if let Some(boot_id) = maybe_boot_id {
            if let Some(cached_stats) = stats.boot_blame.as_ref() {
                let cache_dir = Path::new(&config.boot_blame.cache_dir);
                if let Err(err) =
                    write_cached_boot_blame_to_dir(cache_dir, &boot_id, cached_stats, transport)
                        .await
                {
                    debug!(
                        "Failed to write boot blame cache for boot id {} to {}: {}",
                        boot_id, config.boot_blame.cache_dir, err
                    );
                } else {
                    debug!("Updated boot blame cache for boot id {}", boot_id);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_blame_cache_decode_invalid_payload() {
        // A truncated count, an impossible count and an unknown transport.
        for invalid in [&[0, 1, 2][..], &[255; 4], &[0, 0, 0, 0, 2]] {
            assert!(decode_cached_boot_blame(invalid).is_err());
        }
    }

    #[test]
    fn test_boot_blame_cache_formats() {
        // One entry in the original on-disk format, without a transport byte.
        let legacy = b"\x01\0\0\0\x0b\0\0\0foo.service\0\0\0\0\0\0\xf4\x3f";
        let stats = BootBlameStats::from([("foo.service".to_string(), 1.25)]);
        let decoded = decode_cached_boot_blame(legacy).expect("decode legacy cache");
        assert_eq!(decoded.stats, stats);
        assert_eq!(decoded.transport, None);

        for (marker, transport) in [
            (0, crate::CollectorTransport::Dbus),
            (1, crate::CollectorTransport::Varlink),
        ] {
            let mut tagged = legacy.to_vec();
            tagged.push(marker);
            assert_eq!(encode_cached_boot_blame(&stats, transport).unwrap(), tagged);
            let decoded = decode_cached_boot_blame(&tagged).expect("decode tagged cache");
            assert_eq!(decoded.stats, stats);
            assert_eq!(decoded.transport, Some(transport));
        }
    }

    #[tokio::test]
    async fn test_boot_blame_cache_read_write_roundtrip() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let boot_id = "00000000-0000-0000-0000-000000000001";
        let mut stats = BootBlameStats::new();
        stats.insert("foo.service".to_string(), 1.25);
        stats.insert("bar.service".to_string(), 45.6);

        write_cached_boot_blame_to_dir(
            temp_dir.path(),
            boot_id,
            &stats,
            crate::CollectorTransport::Varlink,
        )
        .await
        .expect("write cache");
        let read = read_cached_boot_blame_from_dir(temp_dir.path(), boot_id)
            .await
            .expect("read cache")
            .expect("cache hit");
        assert_eq!(stats, read.stats);
        assert_eq!(Some(crate::CollectorTransport::Varlink), read.transport);
    }

    #[tokio::test]
    async fn test_boot_blame_cache_read_missing_file() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let missing = read_cached_boot_blame_from_dir(
            temp_dir.path(),
            "00000000-0000-0000-0000-000000000002",
        )
        .await
        .expect("missing cache should not error");
        assert!(missing.is_none());
    }
}
