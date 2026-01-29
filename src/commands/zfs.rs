use crate::commands::runner::{command_exists, run_lines, run_ok, run_table};
use crate::error::{CmdResult, CommandError};
use serde::{Deserialize, Serialize};

/// Check if ZFS is available on the system.
pub async fn is_available() -> bool {
    command_exists("zpool").await && command_exists("zfs").await
}

/// ZFS pool information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pool {
    pub name: String,
    /// Raw pool size (sum of all vdevs)
    pub size: u64,
    /// Raw allocated space
    pub allocated: u64,
    /// Raw free space
    pub free: u64,
    /// Usable space used (from root dataset, accounts for RAID overhead)
    pub used_usable: u64,
    /// Usable space available (from root dataset, accounts for RAID overhead)
    pub available_usable: u64,
    pub fragmentation: u8,
    pub capacity: u8,
    pub health: String,
}

/// List all ZFS pools.
pub async fn list_pools() -> CmdResult<Vec<Pool>> {
    let rows = run_table(
        "zpool",
        &["list", "-Hp", "-o", "name,size,alloc,free,frag,cap,health"],
    )
    .await?;

    let dataset_rows = run_table("zfs", &["list", "-Hp", "-o", "name,used,avail", "-d", "0"])
        .await
        .unwrap_or_default();

    let mut pools = Vec::new();
    for row in rows {
        if row.len() >= 7 {
            let pool_name = &row[0];

            let (used_usable, available_usable) = dataset_rows
                .iter()
                .find(|d| d.len() >= 3 && &d[0] == pool_name)
                .map(|d| (d[1].parse().unwrap_or(0), d[2].parse().unwrap_or(0)))
                .unwrap_or((0, 0));

            pools.push(Pool {
                name: pool_name.clone(),
                size: row[1].parse().unwrap_or(0),
                allocated: row[2].parse().unwrap_or(0),
                free: row[3].parse().unwrap_or(0),
                used_usable,
                available_usable,
                fragmentation: row[4].trim_end_matches('%').parse().unwrap_or(0),
                capacity: row[5].trim_end_matches('%').parse().unwrap_or(0),
                health: row[6].clone(),
            });
        }
    }

    Ok(pools)
}

/// Get pool by name.
pub async fn get_pool(name: &str) -> CmdResult<Pool> {
    let pools = list_pools().await?;
    pools
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| CommandError::DeviceNotFound(format!("ZFS pool '{}'", name)))
}

/// Pool status with device tree.
#[derive(Debug, Clone, Serialize)]
pub struct PoolStatus {
    pub name: String,
    pub state: String,
    pub scan: Option<String>,
    pub config: Vec<String>,
    pub errors: Option<String>,
}

/// Get detailed pool status.
pub async fn pool_status(name: &str) -> CmdResult<PoolStatus> {
    let lines = run_lines("zpool", &["status", name]).await?;

    let mut state = String::new();
    let mut scan = None;
    let mut config = Vec::new();
    let mut errors = None;
    let mut in_config = false;

    for line in &lines {
        if line.starts_with("  state:") {
            state = line.trim_start_matches("  state:").trim().to_string();
        } else if line.starts_with("  scan:") {
            scan = Some(line.trim_start_matches("  scan:").trim().to_string());
        } else if line.starts_with("errors:") {
            errors = Some(line.trim_start_matches("errors:").trim().to_string());
        } else if line.contains("NAME") && line.contains("STATE") {
            in_config = true;
        } else if in_config && !line.is_empty() && !line.starts_with("errors") {
            config.push(line.clone());
        }
    }

    Ok(PoolStatus {
        name: name.to_string(),
        state,
        scan,
        config,
        errors,
    })
}

/// RAID level for pool creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RaidLevel {
    Stripe, // No redundancy (single or concat)
    Mirror, // Mirror (RAID1)
    RaidZ1, // RAID-Z1 (single parity)
    RaidZ2, // RAID-Z2 (double parity)
    RaidZ3, // RAID-Z3 (triple parity)
}

impl RaidLevel {
    pub fn as_arg(&self) -> Option<&'static str> {
        match self {
            Self::Stripe => None,
            Self::Mirror => Some("mirror"),
            Self::RaidZ1 => Some("raidz1"),
            Self::RaidZ2 => Some("raidz2"),
            Self::RaidZ3 => Some("raidz3"),
        }
    }

    pub fn min_devices(&self) -> usize {
        match self {
            Self::Stripe => 1,
            Self::Mirror => 2,
            Self::RaidZ1 => 2,
            Self::RaidZ2 => 3,
            Self::RaidZ3 => 4,
        }
    }
}

/// Options for creating a ZFS pool.
#[derive(Debug, Clone, Default)]
pub struct CreatePoolOptions {
    /// Force creation (overwrite existing data)
    pub force: bool,
    /// Sector size shift (9=512, 12=4K, 13=8K)
    pub ashift: Option<u8>,
    /// Compression algorithm (none, lz4, zstd, zstd-7, etc.)
    pub compression: Option<String>,
    /// Enable autoexpand
    pub autoexpand: bool,
    /// Disable atime
    pub atime_off: bool,
    /// Enable POSIX ACLs
    pub posix_acl: bool,
    /// Store xattrs in SA (system attributes)
    pub xattr_sa: bool,
}

impl CreatePoolOptions {
    /// Sensible defaults for NAS usage
    pub fn nas_defaults() -> Self {
        Self {
            force: false,
            ashift: Some(12),
            compression: Some("zstd".to_string()),
            autoexpand: true,
            atime_off: true,
            posix_acl: true,
            xattr_sa: true,
        }
    }
}

/// Create a new ZFS pool.
pub async fn create_pool(
    name: &str,
    level: RaidLevel,
    devices: &[&str],
    options: CreatePoolOptions,
) -> CmdResult<()> {
    if devices.len() < level.min_devices() {
        return Err(CommandError::NotSupported(format!(
            "{:?} requires at least {} devices",
            level,
            level.min_devices()
        )));
    }

    let mut args = vec!["create".to_string()];

    if options.force {
        args.push("-f".to_string());
    }

    // Pool options (-o)
    let ashift = options.ashift.unwrap_or(12);
    args.push("-o".to_string());
    args.push(format!("ashift={}", ashift));

    if options.autoexpand {
        args.push("-o".to_string());
        args.push("autoexpand=on".to_string());
    }

    // Dataset options (-O)
    if let Some(ref comp) = options.compression
        && comp != "none"
    {
        args.push("-O".to_string());
        args.push(format!("compression={}", comp));
    }

    if options.atime_off {
        args.push("-O".to_string());
        args.push("atime=off".to_string());
    }

    if options.posix_acl {
        args.push("-O".to_string());
        args.push("acltype=posixacl".to_string());
    }

    if options.xattr_sa {
        args.push("-O".to_string());
        args.push("xattr=sa".to_string());
    }

    args.push(name.to_string());

    if let Some(level_arg) = level.as_arg() {
        args.push(level_arg.to_string());
    }

    for dev in devices {
        args.push(dev.to_string());
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_ok("zpool", &args_ref).await?;
    Ok(())
}

/// Destroy a ZFS pool.
pub async fn destroy_pool(name: &str, force: bool) -> CmdResult<()> {
    let mut args = vec!["destroy"];
    if force {
        args.push("-f");
    }
    args.push(name);

    run_ok("zpool", &args).await?;
    Ok(())
}

/// Import a ZFS pool.
pub async fn import_pool(name: &str, force: bool) -> CmdResult<()> {
    if force {
        run_ok("zpool", &["import", "-f", name]).await?;
    } else {
        run_ok("zpool", &["import", name]).await?;
    }
    Ok(())
}

/// Import a ZFS pool by ID (for pools with same name).
#[allow(dead_code)]
pub async fn import_pool_by_id(pool_id: &str, name: Option<&str>, force: bool) -> CmdResult<()> {
    let mut args = vec!["import"];
    if force {
        args.push("-f");
    }
    if let Some(n) = name {
        args.push("-N"); // Don't mount
        args.push(pool_id);
        args.push(n);
    } else {
        args.push(pool_id);
    }
    run_ok("zpool", &args).await?;
    Ok(())
}

/// Export a ZFS pool.
pub async fn export_pool(name: &str) -> CmdResult<()> {
    run_ok("zpool", &["export", name]).await?;
    Ok(())
}

/// Force export a ZFS pool (even if busy).
#[allow(dead_code)]
pub async fn export_pool_force(name: &str) -> CmdResult<()> {
    run_ok("zpool", &["export", "-f", name]).await?;
    Ok(())
}

/// Importable pool info
#[derive(Debug, Clone, Serialize)]
pub struct ImportablePool {
    pub name: String,
    pub id: String,
    pub state: String,
}

/// List available pools for import.
pub async fn list_importable() -> CmdResult<Vec<ImportablePool>> {
    let lines = run_lines("zpool", &["import"]).await.unwrap_or_default();

    let mut pools = Vec::new();
    let mut current_name = String::new();
    let mut current_id = String::new();
    let mut current_state = String::new();

    for line in &lines {
        if line.trim().starts_with("pool:") {
            if !current_name.is_empty() {
                pools.push(ImportablePool {
                    name: current_name.clone(),
                    id: current_id.clone(),
                    state: current_state.clone(),
                });
            }
            current_name = line.trim().trim_start_matches("pool:").trim().to_string();
            current_id.clear();
            current_state.clear();
        } else if line.trim().starts_with("id:") {
            current_id = line.trim().trim_start_matches("id:").trim().to_string();
        } else if line.trim().starts_with("state:") {
            current_state = line.trim().trim_start_matches("state:").trim().to_string();
        }
    }

    if !current_name.is_empty() {
        pools.push(ImportablePool {
            name: current_name,
            id: current_id,
            state: current_state,
        });
    }

    Ok(pools)
}

/// Pool property value
#[derive(Debug, Clone, Serialize)]
pub struct PoolProperty {
    pub name: String,
    pub value: String,
    pub source: String,
}

/// Get pool properties
pub async fn get_pool_properties(name: &str) -> CmdResult<Vec<PoolProperty>> {
    let rows = run_table("zpool", &["get", "-Hp", "all", name]).await?;

    let mut props = Vec::new();
    for row in rows {
        if row.len() >= 4 {
            props.push(PoolProperty {
                name: row[1].clone(),
                value: row[2].clone(),
                source: row[3].clone(),
            });
        }
    }

    Ok(props)
}

/// Set a pool property
pub async fn set_pool_property(pool: &str, property: &str, value: &str) -> CmdResult<()> {
    let prop_value = format!("{}={}", property, value);
    run_ok("zpool", &["set", &prop_value, pool]).await?;
    Ok(())
}

/// Start a scrub on a pool.
pub async fn scrub_start(name: &str) -> CmdResult<()> {
    run_ok("zpool", &["scrub", name]).await?;
    Ok(())
}

/// Stop a scrub on a pool.
pub async fn scrub_stop(name: &str) -> CmdResult<()> {
    run_ok("zpool", &["scrub", "-s", name]).await?;
    Ok(())
}

/// Add a vdev to an existing pool.
/// For stripe: just adds disks
/// For mirror: adds a new mirror vdev
/// For raidz: adds a new raidz vdev
pub async fn add_vdev(
    pool: &str,
    level: RaidLevel,
    devices: &[&str],
    force: bool,
) -> CmdResult<()> {
    if devices.is_empty() {
        return Err(CommandError::NotSupported(
            "No devices specified".to_string(),
        ));
    }

    let mut args = vec!["add".to_string()];

    if force {
        args.push("-f".to_string());
    }

    args.push(pool.to_string());

    if let Some(level_arg) = level.as_arg() {
        args.push(level_arg.to_string());
    }

    for dev in devices {
        args.push(dev.to_string());
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_ok("zpool", &args_ref).await?;
    Ok(())
}

/// Add a spare device to a pool.
pub async fn add_spare(pool: &str, device: &str) -> CmdResult<()> {
    run_ok("zpool", &["add", pool, "spare", device]).await?;
    Ok(())
}

/// Add a cache device (L2ARC) to a pool.
pub async fn add_cache(pool: &str, device: &str) -> CmdResult<()> {
    run_ok("zpool", &["add", pool, "cache", device]).await?;
    Ok(())
}

/// Add a log device (SLOG) to a pool.
#[allow(dead_code)]
pub async fn add_log(pool: &str, device: &str) -> CmdResult<()> {
    run_ok("zpool", &["add", pool, "log", device]).await?;
    Ok(())
}

/// Remove a device from a pool (for spares, cache, log, or after evacuation).
#[allow(dead_code)]
pub async fn remove_device(pool: &str, device: &str) -> CmdResult<()> {
    run_ok("zpool", &["remove", pool, device]).await?;
    Ok(())
}

/// Attach a device to a mirror (converts single disk to mirror, or adds to existing mirror).
pub async fn attach_device(
    pool: &str,
    existing_device: &str,
    new_device: &str,
    force: bool,
) -> CmdResult<()> {
    let mut args = vec!["attach"];
    if force {
        args.push("-f");
    }
    args.push(pool);
    args.push(existing_device);
    args.push(new_device);

    run_ok("zpool", &args).await?;
    Ok(())
}

/// Detach a device from a mirror.
#[allow(dead_code)]
pub async fn detach_device(pool: &str, device: &str) -> CmdResult<()> {
    run_ok("zpool", &["detach", pool, device]).await?;
    Ok(())
}

/// Replace a device in a pool.
pub async fn replace_device(
    pool: &str,
    old_device: &str,
    new_device: &str,
    force: bool,
) -> CmdResult<()> {
    let mut args = vec!["replace"];
    if force {
        args.push("-f");
    }
    args.push(pool);
    args.push(old_device);
    args.push(new_device);

    run_ok("zpool", &args).await?;
    Ok(())
}

/// Clear errors on a pool or device.
pub async fn clear_errors(pool: &str, device: Option<&str>) -> CmdResult<()> {
    let mut args = vec!["clear", pool];
    if let Some(dev) = device {
        args.push(dev);
    }
    run_ok("zpool", &args).await?;
    Ok(())
}

/// Get raw zpool status output for display.
pub async fn pool_status_raw(name: &str) -> CmdResult<String> {
    let output = run_ok("zpool", &["status", name]).await?;
    Ok(output.stdout)
}

/// ZFS dataset information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    pub name: String,
    pub used: u64,
    pub available: u64,
    pub referenced: u64,
    pub mountpoint: Option<String>,
    pub compression: String,
    pub quota: Option<u64>,
}

/// List all datasets.
pub async fn list_datasets() -> CmdResult<Vec<Dataset>> {
    let rows = run_table(
        "zfs",
        &[
            "list",
            "-t",
            "filesystem",
            "-Hp",
            "-o",
            "name,used,avail,refer,mountpoint,compression,quota",
        ],
    )
    .await?;

    let mut datasets = Vec::new();
    for row in rows {
        if row.len() >= 7 {
            datasets.push(Dataset {
                name: row[0].clone(),
                used: row[1].parse().unwrap_or(0),
                available: row[2].parse().unwrap_or(0),
                referenced: row[3].parse().unwrap_or(0),
                mountpoint: if row[4] == "none" || row[4] == "-" {
                    None
                } else {
                    Some(row[4].clone())
                },
                compression: row[5].clone(),
                quota: row[6].parse().ok().filter(|&q| q > 0),
            });
        }
    }

    Ok(datasets)
}

/// Get dataset by name.
pub async fn get_dataset(name: &str) -> CmdResult<Dataset> {
    let datasets = list_datasets().await?;
    datasets
        .into_iter()
        .find(|d| d.name == name)
        .ok_or_else(|| CommandError::DeviceNotFound(format!("ZFS dataset '{}'", name)))
}

/// Create a new dataset.
pub async fn create_dataset(name: &str, mountpoint: Option<&str>) -> CmdResult<()> {
    let mut args = vec!["create"];

    let mp_owned: String;
    if let Some(mp) = mountpoint {
        mp_owned = format!("mountpoint={}", mp);
        args.push("-o");
        args.push(&mp_owned);
    }

    args.push(name);

    run_ok("zfs", &args).await?;
    Ok(())
}

/// Destroy a dataset.
pub async fn destroy_dataset(name: &str, recursive: bool) -> CmdResult<()> {
    let mut args = vec!["destroy"];
    if recursive {
        args.push("-r");
    }
    args.push(name);

    run_ok("zfs", &args).await?;
    Ok(())
}

/// Set a property on a dataset.
pub async fn set_property(name: &str, property: &str, value: &str) -> CmdResult<()> {
    let prop_value = format!("{}={}", property, value);
    run_ok("zfs", &["set", &prop_value, name]).await?;
    Ok(())
}

/// Get a property from a dataset.
pub async fn get_property(name: &str, property: &str) -> CmdResult<String> {
    let rows = run_table("zfs", &["get", "-Hp", "-o", "value", property, name]).await?;

    rows.into_iter()
        .next()
        .and_then(|r| r.into_iter().next())
        .ok_or_else(|| CommandError::Parse {
            command: "zfs get".to_string(),
            message: "Empty output".to_string(),
        })
}

/// ZFS snapshot information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub name: String,
    pub dataset: String,
    pub snapshot: String,
    pub used: u64,
    pub referenced: u64,
    pub creation: String,
    pub mountpoint: Option<String>,
}

/// List all snapshots.
pub async fn list_snapshots() -> CmdResult<Vec<Snapshot>> {
    let rows = run_table(
        "zfs",
        &[
            "list",
            "-Hp",
            "-t",
            "snapshot",
            "-o",
            "name,used,refer,creation",
        ],
    )
    .await?;

    let mut snapshots = Vec::new();
    for row in rows {
        if row.len() >= 4 {
            let name = &row[0];
            let parts: Vec<&str> = name.split('@').collect();
            if parts.len() == 2 {
                let mount_name = name.replace(['@', '/'], "_");
                let mount_path = format!("/mnt/snapshots/{}", mount_name);
                let mountpoint = if std::path::Path::new(&mount_path).exists() {
                    Some(mount_path)
                } else {
                    None
                };

                snapshots.push(Snapshot {
                    name: name.clone(),
                    dataset: parts[0].to_string(),
                    snapshot: parts[1].to_string(),
                    used: row[1].parse().unwrap_or(0),
                    referenced: row[2].parse().unwrap_or(0),
                    creation: row[3].clone(),
                    mountpoint,
                });
            }
        }
    }

    Ok(snapshots)
}

/// Create a snapshot.
pub async fn create_snapshot(dataset: &str, snapshot_name: &str) -> CmdResult<()> {
    let full_name = format!("{}@{}", dataset, snapshot_name);
    run_ok("zfs", &["snapshot", &full_name]).await?;
    Ok(())
}

/// Destroy a snapshot.
pub async fn destroy_snapshot(name: &str) -> CmdResult<()> {
    run_ok("zfs", &["destroy", name]).await?;
    Ok(())
}

/// Rollback to a snapshot.
pub async fn rollback(name: &str, force: bool) -> CmdResult<()> {
    let mut args = vec!["rollback"];
    if force {
        args.push("-r");
    }
    args.push(name);

    run_ok("zfs", &args).await?;
    Ok(())
}

/// Get all devices used by ZFS pools (for filtering available disks).
/// Returns device paths (e.g., /dev/sda, /dev/disk/by-id/..., etc.)
pub async fn get_all_pool_devices() -> Vec<String> {
    let mut devices = Vec::new();

    let pools = match list_pools().await {
        Ok(p) => p,
        Err(_) => return devices,
    };

    for pool in pools {
        if let Ok(status) = pool_status(&pool.name).await {
            for line in &status.config {
                let trimmed = line.trim();
                // Skip empty lines, pool name line, and keywords
                if trimmed.is_empty()
                    || trimmed == pool.name
                    || trimmed.starts_with("mirror")
                    || trimmed.starts_with("raidz")
                    || trimmed.starts_with("spare")
                    || trimmed.starts_with("cache")
                    || trimmed.starts_with("log")
                {
                    continue;
                }

                // Extract device name (first word before space)
                if let Some(device_name) = trimmed.split_whitespace().next() {
                    // Skip if it's the pool name or a vdev type
                    if device_name == pool.name {
                        continue;
                    }

                    // Device could be:
                    // - Short name like "sda" or "nvme0n1"
                    // - By-id path like "ata-WDC_WD..."
                    // - Full path like "/dev/sda"

                    devices.push(device_name.to_string());

                    if device_name.starts_with("ata-")
                        || device_name.starts_with("scsi-")
                        || device_name.starts_with("nvme-")
                        || device_name.starts_with("wwn-")
                    {
                        devices.push(format!("/dev/disk/by-id/{}", device_name));
                    }

                    // If it's a short name like "sda", add /dev/sda
                    if !device_name.contains('/') && !device_name.contains('-') {
                        devices.push(format!("/dev/{}", device_name));
                    }
                }
            }
        }
    }

    devices
}
