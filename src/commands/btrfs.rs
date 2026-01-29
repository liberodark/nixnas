use crate::commands::runner::{command_exists, run_lines, run_ok};
use crate::error::CmdResult;
use serde::{Deserialize, Serialize};

/// Check if Btrfs tools are available.
pub async fn is_available() -> bool {
    command_exists("btrfs").await
}

/// Btrfs filesystem information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtrfsFilesystem {
    pub label: Option<String>,
    pub uuid: String,
    pub devices: Vec<BtrfsDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtrfsDevice {
    pub devid: u32,
    pub path: String,
    pub size: u64,
}

/// List all Btrfs filesystems.
pub async fn list_filesystems() -> CmdResult<Vec<BtrfsFilesystem>> {
    let lines = run_lines("btrfs", &["filesystem", "show"]).await?;

    let mut filesystems = Vec::new();
    let mut current: Option<BtrfsFilesystem> = None;

    for line in lines {
        if line.starts_with("Label:") {
            if let Some(fs) = current.take() {
                filesystems.push(fs);
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            let label = parts.get(1).and_then(|s| {
                let s = s.trim_matches('\'');
                if s == "none" {
                    None
                } else {
                    Some(s.to_string())
                }
            });
            let uuid = parts.get(3).map(|s| s.to_string()).unwrap_or_default();

            current = Some(BtrfsFilesystem {
                label,
                uuid,
                devices: Vec::new(),
            });
        } else if line.contains("devid")
            && let Some(ref mut fs) = current
        {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 8
                && let Ok(devid) = parts[1].parse()
            {
                fs.devices.push(BtrfsDevice {
                    devid,
                    path: parts[7].to_string(),
                    size: parse_size(parts[3]).unwrap_or(0),
                });
            }
        }
    }

    if let Some(fs) = current {
        filesystems.push(fs);
    }

    Ok(filesystems)
}

/// Parse size string (e.g., "1.00TiB") to bytes.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let multipliers = [
        ("TiB", 1024u64 * 1024 * 1024 * 1024),
        ("GiB", 1024u64 * 1024 * 1024),
        ("MiB", 1024u64 * 1024),
        ("KiB", 1024u64),
        ("TB", 1000u64 * 1000 * 1000 * 1000),
        ("GB", 1000u64 * 1000 * 1000),
        ("MB", 1000u64 * 1000),
        ("KB", 1000u64),
    ];

    for (suffix, mult) in multipliers {
        if s.ends_with(suffix) {
            let num: f64 = s.trim_end_matches(suffix).parse().ok()?;
            return Some((num * mult as f64) as u64);
        }
    }

    s.parse().ok()
}

/// Btrfs RAID profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BtrfsProfile {
    Single,
    Dup,
    Raid0,
    Raid1,
    Raid1c3,
    Raid1c4,
    Raid5,
    Raid6,
    Raid10,
}

impl BtrfsProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Dup => "dup",
            Self::Raid0 => "raid0",
            Self::Raid1 => "raid1",
            Self::Raid1c3 => "raid1c3",
            Self::Raid1c4 => "raid1c4",
            Self::Raid5 => "raid5",
            Self::Raid6 => "raid6",
            Self::Raid10 => "raid10",
        }
    }
}

/// Create a Btrfs filesystem.
pub async fn create(
    devices: &[&str],
    label: Option<&str>,
    data_profile: BtrfsProfile,
    metadata_profile: BtrfsProfile,
) -> CmdResult<()> {
    let mut args = vec!["-f"];

    let label_owned: String;
    if let Some(l) = label {
        label_owned = l.to_string();
        args.push("-L");
        args.push(&label_owned);
    }

    let data_arg = format!("-d{}", data_profile.as_str());
    let meta_arg = format!("-m{}", metadata_profile.as_str());
    args.push(&data_arg);
    args.push(&meta_arg);

    for dev in devices {
        args.push(dev);
    }

    run_ok("mkfs.btrfs", &args).await?;
    Ok(())
}

/// Btrfs subvolume information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subvolume {
    pub id: u64,
    pub generation: u64,
    pub top_level: u64,
    pub path: String,
}

/// List subvolumes.
pub async fn list_subvolumes(path: &str) -> CmdResult<Vec<Subvolume>> {
    let lines = run_lines("btrfs", &["subvolume", "list", path]).await?;

    let mut subvolumes = Vec::new();
    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 9 {
            subvolumes.push(Subvolume {
                id: parts[1].parse().unwrap_or(0),
                generation: parts[3].parse().unwrap_or(0),
                top_level: parts[6].parse().unwrap_or(0),
                path: parts[8].to_string(),
            });
        }
    }

    Ok(subvolumes)
}

/// Create a subvolume.
pub async fn create_subvolume(path: &str) -> CmdResult<()> {
    run_ok("btrfs", &["subvolume", "create", path]).await?;
    Ok(())
}

/// Delete a subvolume.
pub async fn delete_subvolume(path: &str) -> CmdResult<()> {
    run_ok("btrfs", &["subvolume", "delete", path]).await?;
    Ok(())
}

/// Create a snapshot.
pub async fn create_snapshot(source: &str, dest: &str, readonly: bool) -> CmdResult<()> {
    let mut args = vec!["subvolume", "snapshot"];
    if readonly {
        args.push("-r");
    }
    args.push(source);
    args.push(dest);

    run_ok("btrfs", &args).await?;
    Ok(())
}

/// Get subvolume information.
pub async fn subvolume_show(path: &str) -> CmdResult<String> {
    let output = run_ok("btrfs", &["subvolume", "show", path]).await?;
    Ok(output.stdout)
}

/// Add a device to a Btrfs filesystem.
pub async fn device_add(device: &str, mountpoint: &str) -> CmdResult<()> {
    run_ok("btrfs", &["device", "add", "-f", device, mountpoint]).await?;
    Ok(())
}

/// Remove a device from a Btrfs filesystem.
pub async fn device_remove(device: &str, mountpoint: &str) -> CmdResult<()> {
    run_ok("btrfs", &["device", "remove", device, mountpoint]).await?;
    Ok(())
}

/// Get device statistics.
pub async fn device_stats(path: &str) -> CmdResult<String> {
    let output = run_ok("btrfs", &["device", "stats", path]).await?;
    Ok(output.stdout)
}

/// Start a scrub.
pub async fn scrub_start(path: &str) -> CmdResult<()> {
    run_ok("btrfs", &["scrub", "start", path]).await?;
    Ok(())
}

/// Get scrub status.
pub async fn scrub_status(path: &str) -> CmdResult<String> {
    let output = run_ok("btrfs", &["scrub", "status", path]).await?;
    Ok(output.stdout)
}

/// Cancel a scrub.
pub async fn scrub_cancel(path: &str) -> CmdResult<()> {
    run_ok("btrfs", &["scrub", "cancel", path]).await?;
    Ok(())
}

/// Start a balance.
pub async fn balance_start(path: &str) -> CmdResult<()> {
    run_ok("btrfs", &["balance", "start", path]).await?;
    Ok(())
}

/// Get balance status.
pub async fn balance_status(path: &str) -> CmdResult<String> {
    let output = run_ok("btrfs", &["balance", "status", path]).await?;
    Ok(output.stdout)
}

/// Cancel a balance.
pub async fn balance_cancel(path: &str) -> CmdResult<()> {
    run_ok("btrfs", &["balance", "cancel", path]).await?;
    Ok(())
}

/// Get filesystem usage.
pub async fn filesystem_usage(path: &str) -> CmdResult<String> {
    let output = run_ok("btrfs", &["filesystem", "usage", path]).await?;
    Ok(output.stdout)
}

/// Defragment a path.
pub async fn defragment(path: &str, recursive: bool) -> CmdResult<()> {
    let mut args = vec!["filesystem", "defragment"];
    if recursive {
        args.push("-r");
    }
    args.push(path);

    run_ok("btrfs", &args).await?;
    Ok(())
}
