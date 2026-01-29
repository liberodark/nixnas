use crate::commands::runner::{command_exists, run_lines, run_ok};
use crate::error::{CmdResult, CommandError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Check if mdadm is available.
pub async fn is_available() -> bool {
    command_exists("mdadm").await
}

/// RAID array information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Array {
    pub device: String,
    pub level: String,
    pub device_count: u32,
    pub size: u64,
    pub state: String,
    pub uuid: Option<String>,
    pub devices: Vec<ArrayDevice>,
    pub rebuild_progress: Option<f32>,
}

/// Device in a RAID array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArrayDevice {
    pub path: String,
    pub number: u32,
    pub state: String,
}

/// List all RAID arrays.
pub async fn list_arrays() -> CmdResult<Vec<Array>> {
    let mdstat_path = std::path::Path::new("/proc/mdstat");
    if !mdstat_path.exists() {
        // md module not loaded, no arrays
        return Ok(Vec::new());
    }

    let mdstat = match run_lines("cat", &["/proc/mdstat"]).await {
        Ok(lines) => lines,
        Err(_) => return Ok(Vec::new()), // No md support
    };

    let mut arrays = Vec::new();
    let mut current_device: Option<String> = None;

    for line in &mdstat {
        if line.starts_with("md") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                current_device = Some(format!("/dev/{}", parts[0].trim_end_matches(':')));
            }
        } else if let Some(ref device) = current_device
            && line.contains("blocks")
        {
            if let Ok(detail) = get_array_detail(device).await {
                arrays.push(detail);
            }
            current_device = None;
        }
    }

    Ok(arrays)
}

/// Get detailed information about an array.
pub async fn get_array_detail(device: &str) -> CmdResult<Array> {
    let lines = run_lines("mdadm", &["--detail", device]).await?;

    let mut info: HashMap<String, String> = HashMap::new();
    let mut devices = Vec::new();
    let mut in_devices = false;

    for line in &lines {
        if line.contains("Number") && line.contains("Major") {
            in_devices = true;
            continue;
        }

        if in_devices {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                devices.push(ArrayDevice {
                    number: parts[0].parse().unwrap_or(0),
                    path: parts.last().unwrap_or(&"").to_string(),
                    state: parts[4..parts.len() - 1].join(" "),
                });
            }
        } else if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_string();
            let value = line[pos + 1..].trim().to_string();
            info.insert(key, value);
        }
    }

    let rebuild_progress = info.get("Rebuild Status").and_then(|s| {
        s.trim_end_matches('%')
            .split_whitespace()
            .next()
            .and_then(|p| p.parse().ok())
    });

    Ok(Array {
        device: device.to_string(),
        level: info.get("Raid Level").cloned().unwrap_or_default(),
        device_count: info
            .get("Raid Devices")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        size: info
            .get("Array Size")
            .and_then(|s| {
                s.split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
            })
            .map(|kb| kb * 1024)
            .unwrap_or(0),
        state: info.get("State").cloned().unwrap_or_default(),
        uuid: info.get("UUID").cloned(),
        devices,
        rebuild_progress,
    })
}

/// RAID level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaidLevel {
    Raid0,
    Raid1,
    Raid4,
    Raid5,
    Raid6,
    Raid10,
}

impl RaidLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Raid0 => "0",
            Self::Raid1 => "1",
            Self::Raid4 => "4",
            Self::Raid5 => "5",
            Self::Raid6 => "6",
            Self::Raid10 => "10",
        }
    }

    pub fn min_devices(&self) -> usize {
        match self {
            Self::Raid0 => 2,
            Self::Raid1 => 2,
            Self::Raid4 => 3,
            Self::Raid5 => 3,
            Self::Raid6 => 4,
            Self::Raid10 => 4,
        }
    }
}

/// Create a new RAID array.
pub async fn create_array(
    device: &str,
    level: RaidLevel,
    devices: &[&str],
    spare_devices: &[&str],
) -> CmdResult<()> {
    if devices.len() < level.min_devices() {
        return Err(CommandError::NotSupported(format!(
            "RAID {} requires at least {} devices",
            level.as_str(),
            level.min_devices()
        )));
    }

    let mut args = vec![
        "--create".to_string(),
        device.to_string(),
        "--run".to_string(), // Don't ask for confirmation
    ];

    if level != RaidLevel::Raid0 {
        args.push("--bitmap=internal".to_string());
    }

    args.push("--level".to_string());
    args.push(level.as_str().to_string());
    args.push("--raid-devices".to_string());
    args.push(devices.len().to_string());

    for dev in devices {
        args.push(dev.to_string());
    }

    if !spare_devices.is_empty() {
        args.push("--spare-devices".to_string());
        args.push(spare_devices.len().to_string());

        for dev in spare_devices {
            args.push(dev.to_string());
        }
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_ok("mdadm", &args_ref).await?;
    Ok(())
}

/// Stop (deactivate) an array.
pub async fn stop_array(device: &str) -> CmdResult<()> {
    run_ok("mdadm", &["--stop", device]).await?;
    Ok(())
}

/// Assemble an existing array.
pub async fn assemble_array(device: &str, devices: &[&str]) -> CmdResult<()> {
    let mut args = vec!["--assemble", device];
    for dev in devices {
        args.push(dev);
    }

    run_ok("mdadm", &args).await?;
    Ok(())
}

/// Scan and assemble all arrays.
pub async fn assemble_scan() -> CmdResult<()> {
    run_ok("mdadm", &["--assemble", "--scan"]).await?;
    Ok(())
}

/// Add a device to an array.
pub async fn add_device(array: &str, device: &str) -> CmdResult<()> {
    run_ok("mdadm", &[array, "--add", device]).await?;
    Ok(())
}

/// Remove a device from an array.
pub async fn remove_device(array: &str, device: &str) -> CmdResult<()> {
    run_ok("mdadm", &[array, "--remove", device]).await?;
    Ok(())
}

/// Mark a device as faulty.
pub async fn fail_device(array: &str, device: &str) -> CmdResult<()> {
    run_ok("mdadm", &[array, "--fail", device]).await?;
    Ok(())
}

/// Replace a device (fail + remove + add).
pub async fn replace_device(array: &str, old_device: &str, new_device: &str) -> CmdResult<()> {
    fail_device(array, old_device).await?;
    remove_device(array, old_device).await?;
    add_device(array, new_device).await?;
    Ok(())
}

/// Generate mdadm.conf entry.
pub async fn scan_config() -> CmdResult<String> {
    let output = run_ok("mdadm", &["--detail", "--scan"]).await?;
    Ok(output.stdout)
}

/// Examine a device for RAID superblock.
pub async fn examine(device: &str) -> CmdResult<String> {
    let output = run_ok("mdadm", &["--examine", device]).await?;
    Ok(output.stdout)
}

/// Zero the superblock on a device.
pub async fn zero_superblock(device: &str) -> CmdResult<()> {
    run_ok("mdadm", &["--zero-superblock", device]).await?;
    Ok(())
}

/// Grow an array (add capacity or change RAID level).
pub async fn grow_array(
    device: &str,
    raid_devices: Option<u32>,
    level: Option<RaidLevel>,
) -> CmdResult<()> {
    let mut args = vec!["--grow", device];

    let raid_devices_str: String;
    if let Some(n) = raid_devices {
        raid_devices_str = n.to_string();
        args.push("--raid-devices");
        args.push(&raid_devices_str);
    }

    if let Some(l) = level {
        args.push("--level");
        args.push(l.as_str());
    }

    run_ok("mdadm", &args).await?;
    Ok(())
}

/// Get current rebuild/resync status.
pub async fn get_sync_status(device: &str) -> CmdResult<Option<SyncStatus>> {
    let array = get_array_detail(device).await?;

    if let Some(progress) = array.rebuild_progress {
        Ok(Some(SyncStatus {
            device: device.to_string(),
            progress,
            state: array.state,
        }))
    } else {
        Ok(None)
    }
}

/// Sync status for an array.
#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    pub device: String,
    pub progress: f32,
    pub state: String,
}
