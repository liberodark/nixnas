use crate::commands::runner::{command_exists, run, run_json_ignore_exit, run_ok};
use crate::error::{CmdResult, CommandError};
use crate::state::SmartPowerMode;
use serde::{Deserialize, Serialize};

/// Check if smartctl is available.
pub async fn is_available() -> bool {
    command_exists("smartctl").await
}

/// Complete SMART information for a device.
#[derive(Debug, Clone, Serialize)]
pub struct SmartInfo {
    pub device: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub capacity: u64,
    pub smart_supported: bool,
    pub smart_enabled: bool,
    pub health_passed: bool,
    pub temperature: Option<i32>,
    pub power_on_hours: Option<u64>,
    pub power_cycle_count: Option<u64>,
    pub attributes: Vec<SmartAttribute>,
}

/// Individual SMART attribute.
#[derive(Debug, Clone, Serialize)]
pub struct SmartAttribute {
    pub id: u8,
    pub name: String,
    pub value: u8,
    pub worst: u8,
    pub threshold: u8,
    pub raw_value: i64,
    pub status: AttributeStatus,
}

/// Status of a SMART attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AttributeStatus {
    Ok,
    Warning,
    Failed,
}

impl AttributeStatus {
    /// Determine status from SMART attribute values
    /// - Failed: value at or below threshold (and threshold > 0)
    /// - Warning: value close to threshold (within 10, and threshold > 0)
    /// - Ok: value is healthy
    fn from_values(value: u8, threshold: u8) -> Self {
        if threshold > 0 && value <= threshold {
            AttributeStatus::Failed
        } else if threshold > 0 && value <= threshold + 10 {
            AttributeStatus::Warning
        } else {
            AttributeStatus::Ok
        }
    }
}

// Raw JSON structures from smartctl
#[derive(Debug, Deserialize)]
struct SmartctlOutput {
    #[serde(default)]
    model_name: Option<String>,
    #[serde(default)]
    serial_number: Option<String>,
    #[serde(default)]
    firmware_version: Option<String>,
    #[serde(default)]
    user_capacity: Option<SmartctlCapacity>,
    #[serde(default)]
    smart_status: Option<SmartctlStatus>,
    #[serde(default)]
    ata_smart_attributes: Option<SmartctlAttributes>,
    #[serde(default)]
    temperature: Option<SmartctlTemperature>,
    #[serde(default)]
    power_on_time: Option<SmartctlPowerOnTime>,
    #[serde(default)]
    power_cycle_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SmartctlCapacity {
    bytes: u64,
}

#[derive(Debug, Deserialize)]
struct SmartctlStatus {
    passed: bool,
}

#[derive(Debug, Deserialize)]
struct SmartctlAttributes {
    table: Vec<SmartctlAttribute>,
}

#[derive(Debug, Deserialize)]
struct SmartctlAttribute {
    id: u8,
    name: String,
    value: u8,
    worst: u8,
    thresh: u8,
    raw: SmartctlRawValue,
}

#[derive(Debug, Deserialize)]
struct SmartctlRawValue {
    value: i64,
}

#[derive(Debug, Deserialize)]
struct SmartctlTemperature {
    current: i32,
}

#[derive(Debug, Deserialize)]
struct SmartctlPowerOnTime {
    hours: u64,
}

/// Get SMART information for a device.
pub async fn get_info(device: &str) -> CmdResult<SmartInfo> {
    let output: SmartctlOutput = run_json_ignore_exit("smartctl", &["-j", "-a", device]).await?;

    let attributes: Vec<SmartAttribute> = output
        .ata_smart_attributes
        .map(|attrs| {
            attrs
                .table
                .into_iter()
                .map(|a| {
                    let status = AttributeStatus::from_values(a.value, a.thresh);

                    SmartAttribute {
                        id: a.id,
                        name: a.name,
                        value: a.value,
                        worst: a.worst,
                        threshold: a.thresh,
                        raw_value: a.raw.value,
                        status,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Extract power on hours from attributes if not in dedicated field
    let power_on_hours = output.power_on_time.map(|p| p.hours).or_else(|| {
        attributes
            .iter()
            .find(|a| a.id == 9)
            .map(|a| a.raw_value as u64)
    });

    // Extract power cycle count from attributes if not in dedicated field
    let power_cycle_count = output.power_cycle_count.or_else(|| {
        attributes
            .iter()
            .find(|a| a.id == 12)
            .map(|a| a.raw_value as u64)
    });

    Ok(SmartInfo {
        device: device.to_string(),
        model: output.model_name.unwrap_or_default(),
        serial: output.serial_number.unwrap_or_default(),
        firmware: output.firmware_version.unwrap_or_default(),
        capacity: output.user_capacity.map(|c| c.bytes).unwrap_or(0),
        smart_supported: output.smart_status.is_some(),
        smart_enabled: output.smart_status.is_some(),
        health_passed: output.smart_status.map(|s| s.passed).unwrap_or(false),
        temperature: output.temperature.map(|t| t.current),
        power_on_hours,
        power_cycle_count,
        attributes,
    })
}

/// Get SMART information with power mode check.
/// Returns Err if disk is in power-saving mode and should not be woken.
pub async fn get_info_with_powermode(
    device: &str,
    power_mode: &SmartPowerMode,
) -> CmdResult<SmartInfo> {
    let args: Vec<&str> = match power_mode {
        SmartPowerMode::Never => vec!["-j", "-a", device],
        SmartPowerMode::Sleep => vec!["-j", "-a", "-n", "sleep", device],
        SmartPowerMode::Standby => vec!["-j", "-a", "-n", "standby", device],
        SmartPowerMode::Idle => vec!["-j", "-a", "-n", "idle", device],
    };

    let output: SmartctlOutput = run_json_ignore_exit("smartctl", &args).await?;

    let attributes: Vec<SmartAttribute> = output
        .ata_smart_attributes
        .map(|attrs| {
            attrs
                .table
                .into_iter()
                .map(|a| {
                    let status = AttributeStatus::from_values(a.value, a.thresh);

                    SmartAttribute {
                        id: a.id,
                        name: a.name,
                        value: a.value,
                        worst: a.worst,
                        threshold: a.thresh,
                        raw_value: a.raw.value,
                        status,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let power_on_hours = output.power_on_time.map(|p| p.hours).or_else(|| {
        attributes
            .iter()
            .find(|a| a.id == 9)
            .map(|a| a.raw_value as u64)
    });

    let power_cycle_count = output.power_cycle_count.or_else(|| {
        attributes
            .iter()
            .find(|a| a.id == 12)
            .map(|a| a.raw_value as u64)
    });

    Ok(SmartInfo {
        device: device.to_string(),
        model: output.model_name.unwrap_or_default(),
        serial: output.serial_number.unwrap_or_default(),
        firmware: output.firmware_version.unwrap_or_default(),
        capacity: output.user_capacity.map(|c| c.bytes).unwrap_or(0),
        smart_supported: output.smart_status.is_some(),
        smart_enabled: output.smart_status.is_some(),
        health_passed: output.smart_status.map(|s| s.passed).unwrap_or(false),
        temperature: output.temperature.map(|t| t.current),
        power_on_hours,
        power_cycle_count,
        attributes,
    })
}

/// Quick health check.
pub async fn health_check(device: &str) -> CmdResult<bool> {
    let info = get_info(device).await?;
    Ok(info.health_passed)
}

/// Test type for SMART self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestType {
    Short,
    Long,
    Conveyance,
}

impl TestType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Short => "short",
            Self::Long => "long",
            Self::Conveyance => "conveyance",
        }
    }
}

/// Start a SMART self-test.
/// Note: Exit code 4 means a test is already in progress, which is acceptable.
pub async fn start_test(device: &str, test_type: TestType) -> CmdResult<()> {
    let output = run("smartctl", &["-t", test_type.as_str(), device]).await?;
    // Exit code 4 = test already running, that's OK
    if output.success || output.code == 4 {
        Ok(())
    } else {
        Err(CommandError::Failed {
            command: format!("smartctl -t {} {}", test_type.as_str(), device),
            code: output.code,
            stderr: output.stderr,
        })
    }
}

/// Abort a running self-test.
pub async fn abort_test(device: &str) -> CmdResult<()> {
    run_ok("smartctl", &["-X", device]).await?;
    Ok(())
}

/// Self-test result entry.
#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub num: u32,
    pub description: String,
    pub status: String,
    pub remaining_percent: u8,
    pub lifetime_hours: u64,
}

/// Get self-test log.
pub async fn get_test_results(device: &str) -> CmdResult<Vec<TestResult>> {
    #[derive(Debug, Deserialize)]
    struct TestLogOutput {
        #[serde(default)]
        ata_smart_self_test_log: Option<TestLog>,
    }

    #[derive(Debug, Deserialize)]
    struct TestLog {
        #[serde(default)]
        table: Vec<TestEntry>,
    }

    #[derive(Debug, Deserialize)]
    struct TestEntry {
        #[serde(rename = "type")]
        test_type: TestTypeInfo,
        status: TestStatus,
        lifetime_hours: u64,
    }

    #[derive(Debug, Deserialize)]
    struct TestTypeInfo {
        string: String,
    }

    #[derive(Debug, Deserialize)]
    struct TestStatus {
        string: String,
        #[serde(default)]
        remaining_percent: u8,
    }

    let output: TestLogOutput =
        run_json_ignore_exit("smartctl", &["-j", "-l", "selftest", device]).await?;

    let results = output
        .ata_smart_self_test_log
        .map(|log| {
            log.table
                .into_iter()
                .enumerate()
                .map(|(i, e)| TestResult {
                    num: i as u32 + 1,
                    description: e.test_type.string,
                    status: e.status.string,
                    remaining_percent: e.status.remaining_percent,
                    lifetime_hours: e.lifetime_hours,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(results)
}

/// Get the current power mode of a device.
pub async fn get_power_mode(device: &str) -> CmdResult<String> {
    let output = run_ok("smartctl", &["-i", "-n", "standby", device]).await;

    match output {
        Ok(_) => Ok("active".to_string()),
        Err(_) => Ok("standby".to_string()),
    }
}
