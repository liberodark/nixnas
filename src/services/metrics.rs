use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};

/// Maximum number of data points to keep (24h at 1 point/minute = 1440)
const MAX_HISTORY_POINTS: usize = 1440;

/// Metrics storage
#[derive(Clone)]
pub struct MetricsStore {
    inner: Arc<RwLock<MetricsData>>,
}

#[derive(Default)]
struct MetricsData {
    cpu: VecDeque<MetricPoint>,
    memory: VecDeque<MetricPoint>,
    network_rx: VecDeque<MetricPoint>,
    network_tx: VecDeque<MetricPoint>,
    disk_io_read: VecDeque<MetricPoint>,
    disk_io_write: VecDeque<MetricPoint>,
    temperatures: VecDeque<TempPoint>,
    load: VecDeque<LoadPoint>,
    /// Last network bytes for delta calculation
    last_net_rx: u64,
    last_net_tx: u64,
    /// Last disk bytes for delta calculation
    last_disk_read: u64,
    last_disk_write: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub timestamp: i64,
    pub value: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TempPoint {
    pub timestamp: i64,
    pub temps: Vec<(String, i32)>, // (device, temp)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoadPoint {
    pub timestamp: i64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
}

/// Current snapshot of all metrics (for WebSocket)
#[derive(Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: i64,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub memory_used: u64,
    pub memory_total: u64,
    pub swap_percent: f64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub temperatures: Vec<(String, i32)>,
    pub uptime_secs: u64,
}

/// Historical data for charts
#[derive(Clone, Serialize, Deserialize)]
pub struct MetricsHistory {
    pub cpu: Vec<MetricPoint>,
    pub memory: Vec<MetricPoint>,
    pub network_rx: Vec<MetricPoint>,
    pub network_tx: Vec<MetricPoint>,
    pub disk_read: Vec<MetricPoint>,
    pub disk_write: Vec<MetricPoint>,
    pub load: Vec<LoadPoint>,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MetricsData::default())),
        }
    }

    /// Start the metrics collection background task
    pub fn start_collection(self: Arc<Self>) {
        let store = Arc::clone(&self);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Collect every minute

            loop {
                interval.tick().await;
                if let Err(e) = store.collect().await {
                    tracing::error!("Metrics collection failed: {}", e);
                }
            }
        });

        tracing::info!("Metrics collection service started");
    }

    /// Collect current metrics and store
    async fn collect(&self) -> Result<(), String> {
        let snapshot = Self::gather_snapshot().await?;
        let timestamp = snapshot.timestamp;

        let mut data = self.inner.write().await;

        push_metric(
            &mut data.cpu,
            MetricPoint {
                timestamp,
                value: snapshot.cpu_percent,
            },
        );

        push_metric(
            &mut data.memory,
            MetricPoint {
                timestamp,
                value: snapshot.memory_percent,
            },
        );

        let net_rx_delta = snapshot.network_rx_bytes.saturating_sub(data.last_net_rx);
        let net_tx_delta = snapshot.network_tx_bytes.saturating_sub(data.last_net_tx);
        data.last_net_rx = snapshot.network_rx_bytes;
        data.last_net_tx = snapshot.network_tx_bytes;

        if net_rx_delta > 0 || data.network_rx.is_empty() {
            push_metric(
                &mut data.network_rx,
                MetricPoint {
                    timestamp,
                    value: net_rx_delta as f64 / 60.0, // bytes per second
                },
            );
        }
        if net_tx_delta > 0 || data.network_tx.is_empty() {
            push_metric(
                &mut data.network_tx,
                MetricPoint {
                    timestamp,
                    value: net_tx_delta as f64 / 60.0,
                },
            );
        }

        // Disk I/O (calculate delta)
        let disk_read_delta = snapshot.disk_read_bytes.saturating_sub(data.last_disk_read);
        let disk_write_delta = snapshot
            .disk_write_bytes
            .saturating_sub(data.last_disk_write);
        data.last_disk_read = snapshot.disk_read_bytes;
        data.last_disk_write = snapshot.disk_write_bytes;

        push_metric(
            &mut data.disk_io_read,
            MetricPoint {
                timestamp,
                value: disk_read_delta as f64 / 60.0,
            },
        );
        push_metric(
            &mut data.disk_io_write,
            MetricPoint {
                timestamp,
                value: disk_write_delta as f64 / 60.0,
            },
        );

        push_temp(
            &mut data.temperatures,
            TempPoint {
                timestamp,
                temps: snapshot.temperatures.clone(),
            },
        );

        push_load(
            &mut data.load,
            LoadPoint {
                timestamp,
                load1: snapshot.load1,
                load5: snapshot.load5,
                load15: snapshot.load15,
            },
        );

        Ok(())
    }

    /// Get current metrics snapshot
    pub async fn get_snapshot() -> Result<MetricsSnapshot, String> {
        Self::gather_snapshot().await
    }

    /// Gather all current metrics
    async fn gather_snapshot() -> Result<MetricsSnapshot, String> {
        let timestamp = chrono::Utc::now().timestamp();

        let cpu_percent = Self::read_cpu_usage().await.unwrap_or(0.0);

        let (memory_used, memory_total, swap_percent) =
            Self::read_memory().await.unwrap_or((0, 1, 0.0));
        let memory_percent = (memory_used as f64 / memory_total as f64) * 100.0;

        let (load1, load5, load15) = Self::read_load().await.unwrap_or((0.0, 0.0, 0.0));

        let (network_rx, network_tx) = Self::read_network().await.unwrap_or((0, 0));

        let (disk_read, disk_write) = Self::read_disk_io().await.unwrap_or((0, 0));

        let temperatures = Self::read_temperatures().await.unwrap_or_default();

        let uptime_secs = Self::read_uptime().await.unwrap_or(0);

        Ok(MetricsSnapshot {
            timestamp,
            cpu_percent,
            memory_percent,
            memory_used,
            memory_total,
            swap_percent,
            load1,
            load5,
            load15,
            network_rx_bytes: network_rx,
            network_tx_bytes: network_tx,
            disk_read_bytes: disk_read,
            disk_write_bytes: disk_write,
            temperatures,
            uptime_secs,
        })
    }

    /// Get historical metrics
    pub async fn get_history(&self, minutes: usize) -> MetricsHistory {
        let data = self.inner.read().await;
        let limit = minutes.min(MAX_HISTORY_POINTS);

        MetricsHistory {
            cpu: data.cpu.iter().rev().take(limit).rev().cloned().collect(),
            memory: data
                .memory
                .iter()
                .rev()
                .take(limit)
                .rev()
                .cloned()
                .collect(),
            network_rx: data
                .network_rx
                .iter()
                .rev()
                .take(limit)
                .rev()
                .cloned()
                .collect(),
            network_tx: data
                .network_tx
                .iter()
                .rev()
                .take(limit)
                .rev()
                .cloned()
                .collect(),
            disk_read: data
                .disk_io_read
                .iter()
                .rev()
                .take(limit)
                .rev()
                .cloned()
                .collect(),
            disk_write: data
                .disk_io_write
                .iter()
                .rev()
                .take(limit)
                .rev()
                .cloned()
                .collect(),
            load: data.load.iter().rev().take(limit).rev().cloned().collect(),
        }
    }

    async fn read_cpu_usage() -> Result<f64, String> {
        // Read /proc/stat twice with a small delay
        let stat1 = tokio::fs::read_to_string("/proc/stat")
            .await
            .map_err(|e| e.to_string())?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stat2 = tokio::fs::read_to_string("/proc/stat")
            .await
            .map_err(|e| e.to_string())?;

        fn parse_cpu(line: &str) -> Option<(u64, u64)> {
            let parts: Vec<u64> = line
                .split_whitespace()
                .skip(1)
                .filter_map(|s| s.parse().ok())
                .collect();
            if parts.len() >= 4 {
                let idle = parts.get(3).unwrap_or(&0) + parts.get(4).unwrap_or(&0);
                let total: u64 = parts.iter().take(8).sum();
                Some((idle, total))
            } else {
                None
            }
        }

        let cpu1 = stat1
            .lines()
            .find(|l| l.starts_with("cpu "))
            .and_then(parse_cpu);
        let cpu2 = stat2
            .lines()
            .find(|l| l.starts_with("cpu "))
            .and_then(parse_cpu);

        if let (Some((idle1, total1)), Some((idle2, total2))) = (cpu1, cpu2) {
            let idle_delta = idle2.saturating_sub(idle1);
            let total_delta = total2.saturating_sub(total1);
            if total_delta > 0 {
                return Ok(100.0 * (1.0 - (idle_delta as f64 / total_delta as f64)));
            }
        }

        Ok(0.0)
    }

    async fn read_memory() -> Result<(u64, u64, f64), String> {
        let content = tokio::fs::read_to_string("/proc/meminfo")
            .await
            .map_err(|e| e.to_string())?;

        let mut total = 0u64;
        let mut available = 0u64;
        let mut swap_total = 0u64;
        let mut swap_free = 0u64;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let value: u64 = parts[1].parse().unwrap_or(0) * 1024; // Convert from KB
                match parts[0] {
                    "MemTotal:" => total = value,
                    "MemAvailable:" => available = value,
                    "SwapTotal:" => swap_total = value,
                    "SwapFree:" => swap_free = value,
                    _ => {}
                }
            }
        }

        let used = total.saturating_sub(available);
        let swap_percent = if swap_total > 0 {
            ((swap_total - swap_free) as f64 / swap_total as f64) * 100.0
        } else {
            0.0
        };

        Ok((used, total, swap_percent))
    }

    async fn read_load() -> Result<(f64, f64, f64), String> {
        let content = tokio::fs::read_to_string("/proc/loadavg")
            .await
            .map_err(|e| e.to_string())?;
        let parts: Vec<&str> = content.split_whitespace().collect();

        let load1 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let load5 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let load15 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);

        Ok((load1, load5, load15))
    }

    async fn read_network() -> Result<(u64, u64), String> {
        let content = tokio::fs::read_to_string("/proc/net/dev")
            .await
            .map_err(|e| e.to_string())?;

        let mut rx_total = 0u64;
        let mut tx_total = 0u64;

        for line in content.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let iface = parts[0].trim_end_matches(':');
                if iface == "lo" {
                    continue;
                }
                rx_total += parts
                    .get(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                tx_total += parts
                    .get(9)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }

        Ok((rx_total, tx_total))
    }

    async fn read_disk_io() -> Result<(u64, u64), String> {
        let content = tokio::fs::read_to_string("/proc/diskstats")
            .await
            .map_err(|e| e.to_string())?;

        let mut read_total = 0u64;
        let mut write_total = 0u64;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 14 {
                let device = parts.get(2).unwrap_or(&"");
                if device.starts_with("sd")
                    || device.starts_with("nvme")
                    || device.starts_with("vd")
                {
                    if device
                        .chars()
                        .last()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                        && !device.contains("n1")
                    {
                        continue;
                    }
                    // Fields: sectors read (index 5), sectors written (index 9)
                    read_total += parts
                        .get(5)
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0)
                        * 512;
                    write_total += parts
                        .get(9)
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0)
                        * 512;
                }
            }
        }

        Ok((read_total, write_total))
    }

    async fn read_temperatures() -> Result<Vec<(String, i32)>, String> {
        // Disk temperatures come from SMART cache (refreshed every 5 min by monitoring service)
        // We do NOT call smartctl here - it's too slow for real-time metrics
        let mut temps = Vec::new();

        if let Ok(entries) = std::fs::read_dir("/sys/class/hwmon") {
            for entry in entries.flatten() {
                let hwmon_path = entry.path();

                let name_path = hwmon_path.join("name");
                let name = std::fs::read_to_string(&name_path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());

                // Read temp1_input (main temperature sensor)
                let temp_path = hwmon_path.join("temp1_input");
                if let Ok(content) = std::fs::read_to_string(&temp_path)
                    && let Ok(millidegrees) = content.trim().parse::<i32>()
                {
                    let degrees = millidegrees / 1000;
                    if degrees > 0 && degrees < 150 {
                        temps.push((name, degrees));
                    }
                }
            }
        }

        Ok(temps)
    }

    async fn read_uptime() -> Result<u64, String> {
        let content = tokio::fs::read_to_string("/proc/uptime")
            .await
            .map_err(|e| e.to_string())?;
        let secs: f64 = content
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        Ok(secs as u64)
    }
}

fn push_metric(deque: &mut VecDeque<MetricPoint>, point: MetricPoint) {
    if deque.len() >= MAX_HISTORY_POINTS {
        deque.pop_front();
    }
    deque.push_back(point);
}

fn push_temp(deque: &mut VecDeque<TempPoint>, point: TempPoint) {
    if deque.len() >= MAX_HISTORY_POINTS {
        deque.pop_front();
    }
    deque.push_back(point);
}

fn push_load(deque: &mut VecDeque<LoadPoint>, point: LoadPoint) {
    if deque.len() >= MAX_HISTORY_POINTS {
        deque.pop_front();
    }
    deque.push_back(point);
}
