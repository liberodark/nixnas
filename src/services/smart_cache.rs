use crate::commands::{filesystem, smart};
use crate::state::SmartPowerMode;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

/// Default cache TTL in seconds (5 minutes - smartd handles real monitoring)
const DEFAULT_CACHE_TTL: u64 = 300;

/// Cached SMART data for a single disk
#[derive(Debug, Clone)]
pub struct CachedSmartInfo {
    pub info: smart::SmartInfo,
    pub status: SmartStatus,
    #[allow(dead_code)]
    pub assessment: SmartAssessment,
    #[allow(dead_code)]
    pub updated_at: Instant,
}

/// Overall SMART status for dashboard display
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmartStatus {
    Ok,
    Warning,
    Failed,
}

impl SmartStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SmartStatus::Ok => "ok",
            SmartStatus::Warning => "warning",
            SmartStatus::Failed => "failed",
        }
    }
}

/// Detailed assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmartAssessment {
    /// Disk is healthy
    Good,
    /// Attribute value <= threshold now
    BadAttributeNow,
    /// Attribute worst <= threshold (happened in the past)
    BadAttributeInThePast,
    /// Some bad sectors detected
    BadSector,
    /// Many bad sectors (above dynamic threshold)
    BadSectorMany,
    /// SMART health check failed
    BadStatus,
}

impl SmartAssessment {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            SmartAssessment::Good => "GOOD",
            SmartAssessment::BadAttributeNow => "BAD_ATTRIBUTE_NOW",
            SmartAssessment::BadAttributeInThePast => "BAD_ATTRIBUTE_IN_THE_PAST",
            SmartAssessment::BadSector => "BAD_SECTOR",
            SmartAssessment::BadSectorMany => "BAD_SECTOR_MANY",
            SmartAssessment::BadStatus => "BAD_STATUS",
        }
    }

    pub fn to_status(self) -> SmartStatus {
        match self {
            SmartAssessment::Good => SmartStatus::Ok,
            SmartAssessment::BadAttributeInThePast | SmartAssessment::BadSector => {
                SmartStatus::Warning
            }
            SmartAssessment::BadAttributeNow
            | SmartAssessment::BadSectorMany
            | SmartAssessment::BadStatus => SmartStatus::Failed,
        }
    }
}

/// SMART cache storage
#[derive(Clone)]
pub struct SmartCache {
    inner: Arc<RwLock<SmartCacheInner>>,
    /// Per-device mutexes to prevent parallel smartctl calls
    /// This is critical to avoid increasing ATA error counts
    device_locks: Arc<RwLock<HashMap<String, Arc<Mutex<()>>>>>,
    ttl: Duration,
}

struct SmartCacheInner {
    /// Cached data by disk name (e.g., "sda")
    data: HashMap<String, CachedSmartInfo>,
    /// Last full refresh time
    last_refresh: Option<Instant>,
    /// Is a refresh currently in progress?
    refreshing: bool,
}

/// Disk info for cache refresh
pub struct DiskRefreshInfo {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub power_mode: SmartPowerMode,
}

impl SmartCache {
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(DEFAULT_CACHE_TTL))
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(SmartCacheInner {
                data: HashMap::new(),
                last_refresh: None,
                refreshing: false,
            })),
            device_locks: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Get or create a mutex for a specific device
    async fn get_device_lock(&self, device: &str) -> Arc<Mutex<()>> {
        let mut locks = self.device_locks.write().await;
        locks
            .entry(device.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Check if cache needs refresh
    #[allow(dead_code)]
    pub async fn needs_refresh(&self) -> bool {
        let inner = self.inner.read().await;
        match inner.last_refresh {
            None => true,
            Some(t) => t.elapsed() > self.ttl,
        }
    }

    /// Get cached data for a specific disk
    #[allow(dead_code)]
    pub async fn get(&self, disk_name: &str) -> Option<CachedSmartInfo> {
        let inner = self.inner.read().await;
        inner.data.get(disk_name).cloned()
    }

    /// Get all cached disk data
    #[allow(dead_code)]
    pub async fn get_all(&self) -> Vec<CachedSmartInfo> {
        let inner = self.inner.read().await;
        inner.data.values().cloned().collect()
    }

    /// Get temperatures for all cached disks
    pub async fn get_temperatures(&self) -> Vec<(String, i32)> {
        let inner = self.inner.read().await;
        inner
            .data
            .iter()
            .filter_map(|(name, cached)| cached.info.temperature.map(|t| (name.clone(), t)))
            .collect()
    }

    /// Get status for all cached disks
    pub async fn get_statuses(&self) -> Vec<(String, SmartStatus)> {
        let inner = self.inner.read().await;
        inner
            .data
            .iter()
            .map(|(name, cached)| (name.clone(), cached.status))
            .collect()
    }

    /// Refresh cache for specific disks with power mode awareness
    /// Uses per-device mutex to prevent parallel smartctl calls
    pub async fn refresh_with_config(&self, disks: &[DiskRefreshInfo]) {
        {
            let mut inner = self.inner.write().await;
            if inner.refreshing {
                tracing::debug!("SMART cache refresh already in progress, skipping");
                return;
            }
            inner.refreshing = true;
        }

        if disks.is_empty() {
            let mut inner = self.inner.write().await;
            inner.refreshing = false;
            inner.last_refresh = Some(Instant::now());
            return;
        }

        // Fetch SMART data for each disk sequentially with mutex protection
        // We use sequential here because:
        // 1. Each disk has its own mutex (parallel on different disks is OK)
        // 2. This is background refresh, not blocking UI
        let mut results = Vec::new();

        for disk in disks {
            if is_virtual_disk(&disk.name) {
                continue;
            }

            // Acquire per-device mutex (prevent parallel smartctl calls)
            let lock = self.get_device_lock(&disk.path).await;
            let _guard = lock.lock().await;

            tracing::debug!(
                "Fetching SMART data for {} (power_mode: {:?})",
                disk.name,
                disk.power_mode
            );

            // Use power mode aware fetch to avoid waking sleeping disks
            let result = smart::get_info_with_powermode(&disk.path, &disk.power_mode).await;

            match result {
                Ok(info) => {
                    if info.smart_supported {
                        let assessment = compute_assessment(&info, disk.size);
                        let status = assessment.to_status();
                        results.push((
                            disk.name.clone(),
                            CachedSmartInfo {
                                info,
                                status,
                                assessment,
                                updated_at: Instant::now(),
                            },
                        ));
                    }
                }
                Err(e) => {
                    // Don't log error for disks in sleep/standby mode
                    if !e.to_string().contains("STANDBY") && !e.to_string().contains("SLEEP") {
                        tracing::warn!("Failed to get SMART info for {}: {}", disk.name, e);
                    }
                }
            }
        }

        {
            let mut inner = self.inner.write().await;
            for (name, cached) in results {
                inner.data.insert(name, cached);
            }
            inner.last_refresh = Some(Instant::now());
            inner.refreshing = false;
        }

        tracing::debug!("SMART cache refresh completed");
    }

    /// Refresh cache for specific disks (simple version without power mode)
    pub async fn refresh(&self, disk_names: &[String]) {
        {
            let mut inner = self.inner.write().await;
            if inner.refreshing {
                return;
            }
            inner.refreshing = true;
        }

        let block_devices = match filesystem::list_block_devices().await {
            Ok(devices) => devices,
            Err(e) => {
                tracing::error!("Failed to list block devices: {}", e);
                let mut inner = self.inner.write().await;
                inner.refreshing = false;
                return;
            }
        };

        let disks_to_check: Vec<_> = block_devices
            .iter()
            .filter(|d| d.device_type == "disk")
            .filter(|d| disk_names.is_empty() || disk_names.contains(&d.name))
            .filter(|d| !is_virtual_disk(&d.name))
            .collect();

        if disks_to_check.is_empty() {
            let mut inner = self.inner.write().await;
            inner.refreshing = false;
            inner.last_refresh = Some(Instant::now());
            return;
        }

        // Fetch sequentially with per-device mutex
        let mut results = Vec::new();

        for dev in &disks_to_check {
            let lock = self.get_device_lock(&dev.path).await;
            let _guard = lock.lock().await;

            if let Ok(info) = smart::get_info(&dev.path).await
                && info.smart_supported
            {
                let size = dev.size;
                let assessment = compute_assessment(&info, size);
                let status = assessment.to_status();
                results.push((
                    dev.name.clone(),
                    CachedSmartInfo {
                        info,
                        status,
                        assessment,
                        updated_at: Instant::now(),
                    },
                ));
            }
        }

        {
            let mut inner = self.inner.write().await;
            for (name, cached) in results {
                inner.data.insert(name, cached);
            }
            inner.last_refresh = Some(Instant::now());
            inner.refreshing = false;
        }

        tracing::debug!("SMART cache refreshed for {} disks", disks_to_check.len());
    }

    /// Refresh cache for all physical disks
    #[allow(dead_code)]
    pub async fn refresh_all(&self) {
        self.refresh(&[]).await;
    }

    /// Clear cache
    #[allow(dead_code)]
    pub async fn clear(&self) {
        let mut inner = self.inner.write().await;
        inner.data.clear();
        inner.last_refresh = None;
    }

    /// Get cache age in seconds
    #[allow(dead_code)]
    pub async fn age_secs(&self) -> Option<u64> {
        let inner = self.inner.read().await;
        inner.last_refresh.map(|t| t.elapsed().as_secs())
    }
}

impl Default for SmartCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if disk is virtual (doesn't support SMART)
fn is_virtual_disk(name: &str) -> bool {
    name.starts_with("vd")
        || name.starts_with("xvd")
        || name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("sr")
        || name.starts_with("fd")
        || name.starts_with("dm-")
        || name.starts_with("md")
        || name.starts_with("zram")
}

/// Compute assessment from SMART info
///
/// 1. Check overall SMART health status
/// 2. Calculate dynamic bad sector threshold based on disk size
/// 3. Check for bad sectors (id=5, id=197)
/// 4. Check individual attribute assessments
fn compute_assessment(info: &smart::SmartInfo, disk_size: u64) -> SmartAssessment {
    // 1. Check overall SMART health - if not passed, immediately bad
    if !info.health_passed {
        return SmartAssessment::BadStatus;
    }

    // If no attributes (SAS/NVMe), rely on health status alone
    if info.attributes.is_empty() {
        return SmartAssessment::Good;
    }

    // 2. Count bad sectors (Reallocated_Sector_Ct + Current_Pending_Sector)
    let mut num_bad_sectors: i64 = 0;

    if let Some(attr) = info.attributes.iter().find(|a| a.id == 5) {
        num_bad_sectors += attr.raw_value;
    }
    if let Some(attr) = info.attributes.iter().find(|a| a.id == 197) {
        num_bad_sectors += attr.raw_value;
    }

    // 3. Calculate dynamic threshold based on disk size (from libatasmart)
    // Threshold = log(size / 512) * 1024
    // This scales with disk size - larger disks tolerate more bad sectors
    if disk_size > 0 {
        let sector_threshold = ((disk_size as f64 / 512.0).ln() * 1024.0) as i64;
        if num_bad_sectors >= sector_threshold {
            return SmartAssessment::BadSectorMany;
        }
    }

    // 4. Check individual attribute assessments
    for attr in &info.attributes {
        // Skip attributes without valid threshold
        if attr.threshold == 0 {
            continue;
        }

        // Current value at or below threshold = failing now
        if attr.value <= attr.threshold {
            return SmartAssessment::BadAttributeNow;
        }

        // Worst value at or below threshold = failed in the past
        if attr.worst <= attr.threshold {
            return SmartAssessment::BadAttributeInThePast;
        }
    }

    // 5. Check Reported_Uncorrect (id=187)
    if let Some(attr) = info.attributes.iter().find(|a| a.id == 187)
        && attr.raw_value > 0
    {
        return SmartAssessment::BadAttributeInThePast;
    }

    // 6. Any bad sectors at all is a warning
    if num_bad_sectors > 0 {
        return SmartAssessment::BadSector;
    }

    SmartAssessment::Good
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_threshold() {
        let size_1tb: u64 = 1_000_000_000_000;
        let threshold_1tb = ((size_1tb as f64 / 512.0).ln() * 1024.0) as i64;
        assert!(threshold_1tb > 20000); // Should be around 21000+

        let size_4tb: u64 = 4_000_000_000_000;
        let threshold_4tb = ((size_4tb as f64 / 512.0).ln() * 1024.0) as i64;
        assert!(threshold_4tb > threshold_1tb); // Larger disk = higher threshold

        let size_500gb: u64 = 500_000_000_000;
        let threshold_500gb = ((size_500gb as f64 / 512.0).ln() * 1024.0) as i64;
        assert!(threshold_500gb < threshold_1tb); // Smaller disk = lower threshold
    }

    #[test]
    fn test_assessment_to_status() {
        assert_eq!(SmartAssessment::Good.to_status(), SmartStatus::Ok);
        assert_eq!(SmartAssessment::BadSector.to_status(), SmartStatus::Warning);
        assert_eq!(
            SmartAssessment::BadAttributeInThePast.to_status(),
            SmartStatus::Warning
        );
        assert_eq!(
            SmartAssessment::BadSectorMany.to_status(),
            SmartStatus::Failed
        );
        assert_eq!(
            SmartAssessment::BadAttributeNow.to_status(),
            SmartStatus::Failed
        );
        assert_eq!(SmartAssessment::BadStatus.to_status(), SmartStatus::Failed);
    }
}
