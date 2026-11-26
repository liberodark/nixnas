use crate::commands::filesystem::{self, BlockDevice};
use crate::commands::runner::{command_exists, run, run_json, run_ok};
use crate::error::{CmdResult, CommandError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use uuid::Uuid;

const FSTYPE: &str = "bcachefs";
const SYSFS_ROOT: &str = "/sys/fs/bcachefs";
const SYSFS_MODULE: &str = "/sys/module/bcachefs";

/// Highest replication level accepted by bcachefs (BCH_REPLICAS_MAX).
pub const MAX_REPLICAS: u8 = 4;

/// Check if bcachefs tools are available.
pub async fn is_available() -> bool {
    command_exists("bcachefs").await
}

/// Check if the bcachefs kernel module is currently loaded.
pub fn is_module_loaded() -> bool {
    Path::new(SYSFS_MODULE).exists()
}

/// Bcachefs filesystem information.
#[derive(Debug, Clone, Serialize)]
pub struct BcachefsFilesystem {
    pub uuid: String,
    pub label: Option<String>,
    pub mountpoint: Option<String>,
    pub devices: Vec<BcachefsDevice>,
    /// Live options, only known while the filesystem is mounted.
    pub options: Option<BcachefsOptions>,
}

impl BcachefsFilesystem {
    /// Mountpoint if mounted, otherwise a member device.
    /// Accepted by every command that works on online and offline filesystems.
    fn target(&self) -> Option<&str> {
        self.mountpoint
            .as_deref()
            .or_else(|| self.devices.first().map(|d| d.path.as_str()))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BcachefsDevice {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BcachefsOptions {
    pub data_replicas: u8,
    pub metadata_replicas: u8,
    pub compression: String,
}

/// Compression algorithms supported at format time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    #[default]
    None,
    Lz4,
    Gzip,
    Zstd,
}

impl Compression {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Lz4 => "lz4",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }
}

fn default_replicas() -> u8 {
    1
}

/// Parameters for creating a filesystem.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateOptions {
    pub devices: Vec<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// Number of copies kept for both data and metadata.
    #[serde(default = "default_replicas")]
    pub replicas: u8,
    #[serde(default)]
    pub compression: Compression,
    /// Overwrite devices that already hold a filesystem.
    #[serde(default)]
    pub force: bool,
}

/// Group bcachefs member devices (at any depth) by filesystem UUID.
fn collect_members(devices: &[BlockDevice], out: &mut BTreeMap<String, BcachefsFilesystem>) {
    for dev in devices {
        if dev.fstype.as_deref() == Some(FSTYPE)
            && let Some(uuid) = &dev.uuid
        {
            let fs = out
                .entry(uuid.clone())
                .or_insert_with(|| BcachefsFilesystem {
                    uuid: uuid.clone(),
                    label: None,
                    mountpoint: None,
                    devices: Vec::new(),
                    options: None,
                });
            if fs.label.is_none() {
                fs.label = dev.label.clone().filter(|l| !l.is_empty());
            }
            fs.devices.push(BcachefsDevice {
                path: dev.path.clone(),
                size: dev.size,
            });
        }
        collect_members(&dev.children, out);
    }
}

/// Build the filesystem list from block devices and a map of
/// member device path -> mountpoint.
fn build_filesystems(
    devices: &[BlockDevice],
    mounted_devices: &HashMap<String, String>,
) -> Vec<BcachefsFilesystem> {
    let mut by_uuid = BTreeMap::new();
    collect_members(devices, &mut by_uuid);

    by_uuid
        .into_values()
        .map(|mut fs| {
            fs.mountpoint = fs
                .devices
                .iter()
                .find_map(|d| mounted_devices.get(&d.path))
                .cloned();
            fs
        })
        .collect()
}

/// Map every member device of the mounted bcachefs filesystems to its mountpoint.
/// The kernel reports multi-device sources as "dev1:dev2", with the paths used at mount time.
async fn mounted_devices() -> CmdResult<HashMap<String, String>> {
    let mut map = HashMap::new();

    for mount in filesystem::list_mounts().await? {
        if mount.fstype != FSTYPE {
            continue;
        }
        for source in mount.source.split(':') {
            let path = tokio::fs::canonicalize(source)
                .await
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| source.to_string());
            // Keep the first mount: later ones are usually subvolume mounts.
            map.entry(path).or_insert_with(|| mount.target.clone());
        }
    }

    Ok(map)
}

/// Read the live options of a mounted filesystem from sysfs.
async fn read_options(uuid: &str) -> Option<BcachefsOptions> {
    let dir = Path::new(SYSFS_ROOT).join(uuid).join("options");
    let read = async |name: &str| {
        tokio::fs::read_to_string(dir.join(name))
            .await
            .ok()
            .map(|s| s.trim().to_string())
    };

    Some(BcachefsOptions {
        data_replicas: read("data_replicas").await?.parse().ok()?,
        metadata_replicas: read("metadata_replicas").await?.parse().ok()?,
        compression: read("compression").await?,
    })
}

/// List all bcachefs filesystems, mounted or not.
pub async fn list_filesystems() -> CmdResult<Vec<BcachefsFilesystem>> {
    let devices = filesystem::list_block_devices().await?;
    let mut filesystems = build_filesystems(&devices, &mounted_devices().await?);

    for fs in &mut filesystems {
        if fs.mountpoint.is_some() {
            fs.options = read_options(&fs.uuid).await;
        }
    }

    Ok(filesystems)
}

async fn find_filesystem(uuid: &str) -> CmdResult<BcachefsFilesystem> {
    list_filesystems()
        .await?
        .into_iter()
        .find(|fs| fs.uuid == uuid)
        .ok_or_else(|| CommandError::DeviceNotFound(format!("bcachefs filesystem {uuid}")))
}

/// Mountpoint of a filesystem, required by commands that only work online.
async fn require_mountpoint(uuid: &str) -> CmdResult<String> {
    find_filesystem(uuid).await?.mountpoint.ok_or_else(|| {
        CommandError::NotSupported(format!("bcachefs filesystem {uuid} must be mounted"))
    })
}

/// Build the `bcachefs format` arguments.
fn format_args(opts: &CreateOptions) -> CmdResult<Vec<String>> {
    if opts.devices.is_empty() {
        return Err(CommandError::InvalidArgument(
            "at least one device is required".into(),
        ));
    }
    if !(1..=MAX_REPLICAS).contains(&opts.replicas) {
        return Err(CommandError::InvalidArgument(format!(
            "replicas must be between 1 and {MAX_REPLICAS}"
        )));
    }
    if usize::from(opts.replicas) > opts.devices.len() {
        return Err(CommandError::InvalidArgument(format!(
            "{} replicas need at least {} devices",
            opts.replicas, opts.replicas
        )));
    }

    let mut args = vec!["format".to_string()];
    if opts.force {
        args.push("--force".to_string());
    }
    if let Some(label) = opts.label.as_deref().filter(|l| !l.is_empty()) {
        args.push(format!("--fs_label={label}"));
    }
    args.push(format!("--replicas={}", opts.replicas));
    if opts.compression != Compression::None {
        args.push(format!("--compression={}", opts.compression.as_str()));
    }
    args.extend(opts.devices.iter().cloned());

    Ok(args)
}

/// Create a bcachefs filesystem.
pub async fn create(opts: &CreateOptions) -> CmdResult<()> {
    let args = format_args(opts)?;
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ok("bcachefs", &args_ref).await?;
    Ok(())
}

/// Add a device to a filesystem (mounted or not).
pub async fn device_add(uuid: &str, device: &str, force: bool) -> CmdResult<()> {
    let fs = find_filesystem(uuid).await?;
    let target = fs
        .target()
        .ok_or_else(|| CommandError::DeviceNotFound(format!("bcachefs filesystem {uuid}")))?;

    let mut args = vec!["device", "add"];
    if force {
        args.push("--force");
    }
    args.push(target);
    args.push(device);

    run_ok("bcachefs", &args).await?;
    Ok(())
}

/// Remove a device from its filesystem.
pub async fn device_remove(device: &str) -> CmdResult<()> {
    run_ok("bcachefs", &["device", "remove", device]).await?;
    Ok(())
}

/// Bring a device back online in a running filesystem.
pub async fn device_online(device: &str) -> CmdResult<()> {
    run_ok("bcachefs", &["device", "online", device]).await?;
    Ok(())
}

/// Take a device offline without removing it.
pub async fn device_offline(device: &str) -> CmdResult<()> {
    run_ok("bcachefs", &["device", "offline", device]).await?;
    Ok(())
}

/// Get filesystem usage (human-readable).
pub async fn usage(uuid: &str) -> CmdResult<String> {
    let mountpoint = require_mountpoint(uuid).await?;
    let output = run_ok("bcachefs", &["fs", "usage", "-h", &mountpoint]).await?;
    Ok(output.stdout)
}

/// Get the status of background reconciliation (replication, compression, evacuation).
pub async fn reconcile_status(uuid: &str) -> CmdResult<String> {
    let mountpoint = require_mountpoint(uuid).await?;
    let output = run_ok("bcachefs", &["reconcile", "status", &mountpoint]).await?;
    Ok(output.stdout)
}

/// Scrub state of a filesystem.
#[derive(Debug, Clone, Serialize)]
pub struct ScrubStatus {
    pub running: bool,
    /// Output of the current or last scrub.
    pub log: String,
}

/// Name of the transient systemd unit running the scrub of a filesystem.
/// `bcachefs scrub` stays in the foreground until done, so it runs detached from the daemon.
fn scrub_unit(uuid: &str) -> CmdResult<String> {
    Uuid::parse_str(uuid)
        .map(|u| format!("nixnas-bcachefs-scrub-{}.service", u.hyphenated()))
        .map_err(|_| CommandError::InvalidArgument(format!("invalid filesystem UUID: {uuid}")))
}

/// Start a scrub in the background.
pub async fn scrub_start(uuid: &str) -> CmdResult<()> {
    let unit = scrub_unit(uuid)?;
    let mountpoint = require_mountpoint(uuid).await?;
    let which = run_ok("which", &["bcachefs"]).await?;

    run_ok(
        "systemd-run",
        &[
            "--unit",
            &unit,
            "--collect",
            "--quiet",
            "--property=KillSignal=SIGINT",
            which.stdout.trim(),
            "scrub",
            &mountpoint,
        ],
    )
    .await?;
    Ok(())
}

/// Get scrub status.
pub async fn scrub_status(uuid: &str) -> CmdResult<ScrubStatus> {
    let unit = scrub_unit(uuid)?;
    let state = run("systemctl", &["is-active", &unit]).await?;
    let log = run(
        "journalctl",
        &[
            "--unit",
            &unit,
            "--lines",
            "20",
            "--output",
            "cat",
            "--no-pager",
        ],
    )
    .await?;

    Ok(ScrubStatus {
        running: matches!(state.stdout.trim(), "active" | "activating"),
        log: log.stdout,
    })
}

/// Cancel a running scrub.
pub async fn scrub_cancel(uuid: &str) -> CmdResult<()> {
    run_ok("systemctl", &["stop", &scrub_unit(uuid)?]).await?;
    Ok(())
}

/// List subvolumes below a directory of a mounted filesystem.
pub async fn list_subvolumes(path: &str, snapshots: bool) -> CmdResult<serde_json::Value> {
    let mut args = vec!["subvolume", "list", "--json", "--recursive"];
    if snapshots {
        args.push("--snapshots");
    }
    args.push(path);

    run_json("bcachefs", &args).await
}

/// Create a subvolume.
pub async fn create_subvolume(path: &str) -> CmdResult<()> {
    run_ok("bcachefs", &["subvolume", "create", path]).await?;
    Ok(())
}

/// Delete a subvolume.
pub async fn delete_subvolume(path: &str) -> CmdResult<()> {
    run_ok("bcachefs", &["subvolume", "delete", path]).await?;
    Ok(())
}

/// Create a snapshot.
pub async fn create_snapshot(source: &str, dest: &str, readonly: bool) -> CmdResult<()> {
    let mut args = vec!["subvolume", "snapshot"];
    if readonly {
        args.push("--read-only");
    }
    args.push(source);
    args.push(dest);

    run_ok("bcachefs", &args).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn block_devices() -> Vec<BlockDevice> {
        serde_json::from_value(json!([
            {
                "name": "sda", "path": "/dev/sda", "type": "disk", "size": 1000,
                "fstype": "bcachefs", "uuid": "aaaa", "label": "tank"
            },
            {
                "name": "sdb", "path": "/dev/sdb", "type": "disk", "size": 2000,
                "children": [{
                    "name": "sdb1", "path": "/dev/sdb1", "type": "part", "size": 1500,
                    "fstype": "bcachefs", "uuid": "aaaa", "label": "tank"
                }]
            },
            {
                "name": "sdc", "path": "/dev/sdc", "type": "disk", "size": 3000,
                "fstype": "bcachefs", "uuid": "bbbb"
            },
            {
                "name": "sdd", "path": "/dev/sdd", "type": "disk", "size": 4000,
                "fstype": "ext4", "uuid": "cccc"
            }
        ]))
        .unwrap()
    }

    fn create_options(devices: &[&str], replicas: u8) -> CreateOptions {
        CreateOptions {
            devices: devices.iter().map(|d| d.to_string()).collect(),
            label: None,
            replicas,
            compression: Compression::None,
            force: false,
        }
    }

    #[test]
    fn groups_members_by_uuid_including_partitions() {
        let filesystems = build_filesystems(&block_devices(), &HashMap::new());

        assert_eq!(filesystems.len(), 2);
        assert_eq!(filesystems[0].uuid, "aaaa");
        assert_eq!(filesystems[0].label.as_deref(), Some("tank"));
        let paths: Vec<&str> = filesystems[0]
            .devices
            .iter()
            .map(|d| d.path.as_str())
            .collect();
        assert_eq!(paths, ["/dev/sda", "/dev/sdb1"]);
        assert_eq!(filesystems[1].uuid, "bbbb");
        assert_eq!(filesystems[1].label, None);
    }

    #[test]
    fn resolves_mountpoint_from_any_member() {
        let mounted = HashMap::from([("/dev/sdb1".to_string(), "/mnt/tank".to_string())]);
        let filesystems = build_filesystems(&block_devices(), &mounted);

        assert_eq!(filesystems[0].mountpoint.as_deref(), Some("/mnt/tank"));
        assert_eq!(filesystems[0].target(), Some("/mnt/tank"));
        assert_eq!(filesystems[1].mountpoint, None);
        assert_eq!(filesystems[1].target(), Some("/dev/sdc"));
    }

    #[test]
    fn format_args_cover_all_options() {
        let opts = CreateOptions {
            label: Some("tank".to_string()),
            compression: Compression::Zstd,
            force: true,
            ..create_options(&["/dev/sda", "/dev/sdb"], 2)
        };

        assert_eq!(
            format_args(&opts).unwrap(),
            [
                "format",
                "--force",
                "--fs_label=tank",
                "--replicas=2",
                "--compression=zstd",
                "/dev/sda",
                "/dev/sdb"
            ]
        );
    }

    #[test]
    fn format_args_skip_defaults() {
        assert_eq!(
            format_args(&create_options(&["/dev/sda"], 1)).unwrap(),
            ["format", "--replicas=1", "/dev/sda"]
        );
    }

    #[test]
    fn format_args_reject_invalid_input() {
        assert!(format_args(&create_options(&[], 1)).is_err());
        assert!(format_args(&create_options(&["/dev/sda"], 0)).is_err());
        assert!(format_args(&create_options(&["/dev/sda"], 2)).is_err());
        let many = ["/dev/a", "/dev/b", "/dev/c", "/dev/d", "/dev/e"];
        assert!(format_args(&create_options(&many, MAX_REPLICAS + 1)).is_err());
    }

    #[test]
    fn create_options_deserialize_with_defaults() {
        let opts: CreateOptions =
            serde_json::from_value(json!({ "devices": ["/dev/sda"], "compression": "lz4" }))
                .unwrap();

        assert_eq!(opts.replicas, 1);
        assert_eq!(opts.compression, Compression::Lz4);
        assert!(!opts.force);
    }

    #[test]
    fn scrub_unit_requires_a_uuid() {
        assert_eq!(
            scrub_unit("8F2C1A34-5b6d-4e7f-8a9b-0c1d2e3f4a5b").unwrap(),
            "nixnas-bcachefs-scrub-8f2c1a34-5b6d-4e7f-8a9b-0c1d2e3f4a5b.service"
        );
        assert!(scrub_unit("tank; reboot").is_err());
    }
}
