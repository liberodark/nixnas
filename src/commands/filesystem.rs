use crate::commands::runner::{run_json, run_lines, run_ok};
use crate::error::{CmdResult, CommandError};
use serde::{Deserialize, Serialize};

/// Block device information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDevice {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub device_type: String,
    pub size: u64,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub fstype: Option<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub mountpoint: Option<String>,
    #[serde(default)]
    pub rotational: bool,
    #[serde(default)]
    pub removable: bool,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub children: Vec<BlockDevice>,
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<LsblkDevice>,
}

#[derive(Debug, Deserialize)]
struct LsblkDevice {
    name: String,
    #[serde(rename = "type")]
    device_type: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    fstype: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default)]
    rota: Option<bool>,
    #[serde(default)]
    rm: Option<bool>,
    #[serde(default)]
    tran: Option<String>,
    #[serde(default)]
    children: Option<Vec<LsblkDevice>>,
}

impl From<LsblkDevice> for BlockDevice {
    fn from(d: LsblkDevice) -> Self {
        Self {
            name: d.name.clone(),
            path: format!("/dev/{}", d.name),
            device_type: d.device_type,
            size: d.size.unwrap_or(0),
            model: d.model.map(|s| s.trim().to_string()),
            vendor: d.vendor.map(|s| s.trim().to_string()),
            serial: d.serial,
            fstype: d.fstype,
            uuid: d.uuid,
            label: d.label,
            mountpoint: d.mountpoint,
            rotational: d.rota.unwrap_or(true),
            removable: d.rm.unwrap_or(false),
            transport: d.tran,
            children: d
                .children
                .unwrap_or_default()
                .into_iter()
                .map(BlockDevice::from)
                .collect(),
        }
    }
}

/// List all block devices.
pub async fn list_block_devices() -> CmdResult<Vec<BlockDevice>> {
    let output: LsblkOutput = run_json(
        "lsblk",
        &[
            "-J",
            "-b",
            "-o",
            "NAME,TYPE,SIZE,MODEL,VENDOR,SERIAL,FSTYPE,UUID,LABEL,MOUNTPOINT,ROTA,RM,TRAN",
        ],
    )
    .await?;

    Ok(output
        .blockdevices
        .into_iter()
        .map(BlockDevice::from)
        .collect())
}

/// List only physical disks (excluding partitions, loops, etc.).
pub async fn list_disks() -> CmdResult<Vec<BlockDevice>> {
    let devices = list_block_devices().await?;
    Ok(devices
        .into_iter()
        .filter(|d| d.device_type == "disk")
        .collect())
}

/// Get information about a specific device.
pub async fn get_device(path: &str) -> CmdResult<BlockDevice> {
    let output: LsblkOutput = run_json(
        "lsblk",
        &[
            "-J",
            "-b",
            "-o",
            "NAME,TYPE,SIZE,MODEL,VENDOR,SERIAL,FSTYPE,UUID,LABEL,MOUNTPOINT,ROTA,RM,TRAN",
            path,
        ],
    )
    .await?;

    output
        .blockdevices
        .into_iter()
        .next()
        .map(BlockDevice::from)
        .ok_or_else(|| CommandError::DeviceNotFound(path.to_string()))
}

/// Mount point information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: String,
}

#[derive(Debug, Deserialize)]
struct FindmntOutput {
    filesystems: Vec<FindmntEntry>,
}

#[derive(Debug, Deserialize)]
struct FindmntEntry {
    source: String,
    target: String,
    fstype: String,
    options: String,
}

/// List all mount points.
pub async fn list_mounts() -> CmdResult<Vec<MountInfo>> {
    let output: FindmntOutput = run_json("findmnt", &["-J", "-l"]).await?;

    Ok(output
        .filesystems
        .into_iter()
        .map(|e| MountInfo {
            source: e.source,
            target: e.target,
            fstype: e.fstype,
            options: e.options,
        })
        .collect())
}

/// Check if a path is mounted.
pub async fn is_mounted(path: &str) -> CmdResult<bool> {
    let mounts = list_mounts().await?;
    Ok(mounts.iter().any(|m| m.target == path || m.source == path))
}

/// Mount a device to a path.
pub async fn mount(device: &str, target: &str, fstype: Option<&str>) -> CmdResult<()> {
    let mut args = vec![device, target];

    let fstype_owned: String;
    if let Some(fs) = fstype {
        fstype_owned = fs.to_string();
        args.insert(0, "-t");
        args.insert(1, &fstype_owned);
    }

    run_ok("mount", &args).await?;
    Ok(())
}

/// Unmount a path.
pub async fn umount(target: &str) -> CmdResult<()> {
    run_ok("umount", &[target]).await?;
    Ok(())
}

/// Force unmount (lazy).
pub async fn umount_lazy(target: &str) -> CmdResult<()> {
    run_ok("umount", &["-l", target]).await?;
    Ok(())
}

/// Supported filesystem types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FsType {
    Ext4,
    Xfs,
    Btrfs,
    Vfat,
    Ntfs,
}

impl FsType {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Xfs => "xfs",
            Self::Btrfs => "btrfs",
            Self::Vfat => "vfat",
            Self::Ntfs => "ntfs",
        }
    }

    pub fn mkfs_command(&self) -> &'static str {
        match self {
            Self::Ext4 => "mkfs.ext4",
            Self::Xfs => "mkfs.xfs",
            Self::Btrfs => "mkfs.btrfs",
            Self::Vfat => "mkfs.vfat",
            Self::Ntfs => "mkfs.ntfs",
        }
    }
}

/// Create a filesystem on a device.
pub async fn mkfs(device: &str, fstype: FsType, label: Option<&str>) -> CmdResult<()> {
    let mut args: Vec<String> = Vec::new();

    match fstype {
        FsType::Ext4 => args.push("-F".to_string()),
        FsType::Xfs => args.push("-f".to_string()),
        FsType::Btrfs => args.push("-f".to_string()),
        FsType::Ntfs => args.push("-F".to_string()),
        FsType::Vfat => {}
    }

    if let Some(l) = label {
        match fstype {
            FsType::Ext4 | FsType::Btrfs | FsType::Xfs | FsType::Ntfs => {
                args.push("-L".to_string());
                args.push(l.to_string());
            }
            FsType::Vfat => {
                args.push("-n".to_string());
                args.push(l.to_string());
            }
        }
    }

    args.push(device.to_string());

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_ok(fstype.mkfs_command(), &args_ref).await?;
    Ok(())
}

/// Resize a filesystem to fill its partition.
pub async fn resize_fs(device: &str, fstype: &str) -> CmdResult<()> {
    match fstype {
        "ext4" | "ext3" | "ext2" => {
            run_ok("resize2fs", &[device]).await?;
        }
        "xfs" => {
            // XFS needs mountpoint, not device
            let mounts = list_mounts().await?;
            let mount = mounts.iter().find(|m| m.source == device).ok_or_else(|| {
                CommandError::NotSupported("XFS must be mounted to resize".into())
            })?;
            run_ok("xfs_growfs", &[&mount.target]).await?;
        }
        "btrfs" => {
            let mounts = list_mounts().await?;
            let mount = mounts.iter().find(|m| m.source == device).ok_or_else(|| {
                CommandError::NotSupported("Btrfs must be mounted to resize".into())
            })?;
            run_ok("btrfs", &["filesystem", "resize", "max", &mount.target]).await?;
        }
        _ => {
            return Err(CommandError::NotSupported(format!(
                "Resize not supported for {}",
                fstype
            )));
        }
    }
    Ok(())
}

/// Wipe all signatures and partition table from a device.
pub async fn wipe_device(device: &str) -> CmdResult<()> {
    run_ok("wipefs", &["-a", device]).await?;
    let _ = run_ok("sgdisk", &["-Z", device]).await;
    Ok(())
}

/// Wipe partition table with sgdisk.
pub async fn zap_disk(device: &str) -> CmdResult<()> {
    run_ok("sgdisk", &["--zap-all", device]).await?;
    Ok(())
}

/// Get filesystem usage.
#[derive(Debug, Clone, Serialize)]
pub struct FsUsage {
    pub filesystem: String,
    pub size: u64,
    pub used: u64,
    pub available: u64,
    pub use_percent: u8,
    pub mountpoint: String,
}

/// Get usage for all mounted filesystems.
pub async fn get_usage() -> CmdResult<Vec<FsUsage>> {
    let lines = run_lines(
        "df",
        &["-B1", "--output=source,size,used,avail,pcent,target"],
    )
    .await?;

    let mut result = Vec::new();

    for line in lines.iter().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            result.push(FsUsage {
                filesystem: parts[0].to_string(),
                size: parts[1].parse().unwrap_or(0),
                used: parts[2].parse().unwrap_or(0),
                available: parts[3].parse().unwrap_or(0),
                use_percent: parts[4].trim_end_matches('%').parse().unwrap_or(0),
                mountpoint: parts[5].to_string(),
            });
        }
    }

    Ok(result)
}

/// Disk with stable by-id path
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct DiskById {
    pub name: String,
    pub path: String,
    pub by_id: Option<String>,
    pub size: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub rotational: bool,
}

/// Get mapping of disk names to their /dev/disk/by-id/ paths.
pub async fn get_disk_by_id_map() -> CmdResult<std::collections::HashMap<String, String>> {
    use std::collections::HashMap;

    let mut map = HashMap::new();
    let by_id_path = std::path::Path::new("/dev/disk/by-id");

    if let Ok(entries) = std::fs::read_dir(by_id_path) {
        for entry in entries.flatten() {
            let link_name = entry.file_name().to_string_lossy().to_string();

            // Skip partition links and wwn links (prefer ata/scsi/nvme)
            if link_name.contains("-part") || link_name.starts_with("wwn-") {
                continue;
            }

            if let Ok(target) = std::fs::read_link(entry.path())
                && let Some(device_name) = target.file_name()
            {
                let device = device_name.to_string_lossy().to_string();
                let by_id = format!("/dev/disk/by-id/{}", link_name);

                // Prefer ata- or nvme- over scsi-
                if !map.contains_key(&device)
                    || link_name.starts_with("ata-")
                    || link_name.starts_with("nvme-")
                {
                    map.insert(device, by_id);
                }
            }
        }
    }

    Ok(map)
}

/// List all block devices with by-id paths
#[allow(dead_code)]
pub async fn list_disks_with_by_id() -> CmdResult<Vec<DiskById>> {
    let devices = list_block_devices().await?;
    let by_id_map = get_disk_by_id_map().await?;

    let mut disks = Vec::new();

    for dev in devices {
        if dev.device_type == "disk" {
            let by_id = by_id_map.get(&dev.name).cloned();
            disks.push(DiskById {
                name: dev.name,
                path: dev.path,
                by_id,
                size: dev.size,
                model: dev.model,
                serial: dev.serial,
                rotational: dev.rotational,
            });
        }
    }

    Ok(disks)
}

/// Format a device with the specified filesystem.
pub async fn format_device(
    device: &str,
    fstype: &str,
    label: Option<&str>,
    force: bool,
) -> CmdResult<()> {
    let (cmd, args) = match fstype {
        "ext4" => {
            let mut a = vec!["-t", "ext4"];
            if force {
                a.push("-F");
            }
            if let Some(l) = label {
                a.push("-L");
                a.push(l);
            }
            a.push(device);
            ("mkfs", a)
        }
        "xfs" => {
            let mut a = vec!["-t", "xfs"];
            if force {
                a.push("-f");
            }
            if let Some(l) = label {
                a.push("-L");
                a.push(l);
            }
            a.push(device);
            ("mkfs", a)
        }
        "btrfs" => {
            let mut a = vec![];
            if force {
                a.push("-f");
            }
            if let Some(l) = label {
                a.push("-L");
                a.push(l);
            }
            a.push(device);
            ("mkfs.btrfs", a)
        }
        "ntfs" => {
            let mut a = vec!["-Q"]; // Quick format
            if force {
                a.push("-F");
            }
            if let Some(l) = label {
                a.push("-L");
                a.push(l);
            }
            a.push(device);
            ("mkfs.ntfs", a)
        }
        "exfat" => {
            let mut a = vec![];
            if let Some(l) = label {
                a.push("-n");
                a.push(l);
            }
            a.push(device);
            ("mkfs.exfat", a)
        }
        "vfat" | "fat32" => {
            let mut a = vec!["-F", "32"];
            if let Some(l) = label {
                a.push("-n");
                a.push(l);
            }
            a.push(device);
            ("mkfs.vfat", a)
        }
        _ => {
            return Err(CommandError::NotSupported(format!(
                "Unknown filesystem type: {}",
                fstype
            )));
        }
    };

    run_ok(cmd, &args).await?;
    Ok(())
}
