use crate::commands::{filesystem, smart, zfs};
use crate::services::notifications::NotificationService;
use crate::services::smart_cache::SmartCache;
use crate::state::StateManager;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};

/// Monitoring service that runs background checks
pub struct MonitoringService {
    state_manager: Arc<StateManager>,
    smart_cache: Arc<SmartCache>,
    /// Track which alerts have been sent to avoid spam
    sent_alerts: Arc<RwLock<SentAlerts>>,
}

#[derive(Default)]
struct SentAlerts {
    /// Disks with space warnings already sent (mountpoint)
    disk_space: HashSet<String>,
    /// Disks with SMART errors already sent (device)
    smart_errors: HashSet<String>,
    /// ZFS pools with errors already sent (pool name)
    zfs_errors: HashSet<String>,
    /// Disks with high temp already sent (device)
    high_temp: HashSet<String>,
    /// Services that failed (service name)
    service_failures: HashSet<String>,
}

impl MonitoringService {
    pub fn new(state_manager: Arc<StateManager>, smart_cache: Arc<SmartCache>) -> Self {
        Self {
            state_manager,
            smart_cache,
            sent_alerts: Arc::new(RwLock::new(SentAlerts::default())),
        }
    }

    /// Start all monitoring tasks
    pub fn start(self: Arc<Self>) {
        let self1 = Arc::clone(&self);
        let self2 = Arc::clone(&self);
        let self3 = Arc::clone(&self);
        let self4 = Arc::clone(&self);
        let self5 = Arc::clone(&self);
        let self6 = Arc::clone(&self);

        // SMART cache refresh - every 5 minutes (just for UI display, smartd handles real monitoring)
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                self1.refresh_smart_cache().await;
            }
        });

        // Disk space check - every 5 minutes
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                if let Err(e) = self2.check_disk_space().await {
                    tracing::error!("Disk space check failed: {}", e);
                }
            }
        });

        // SMART check - every hour (for notifications, supplements smartd)
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Err(e) = self3.check_smart().await {
                    tracing::error!("SMART check failed: {}", e);
                }
            }
        });

        // ZFS check - every 5 minutes
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                if let Err(e) = self4.check_zfs().await {
                    tracing::error!("ZFS check failed: {}", e);
                }
            }
        });

        // Temperature check - every 5 minutes
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                if let Err(e) = self5.check_temperatures().await {
                    tracing::error!("Temperature check failed: {}", e);
                }
            }
        });

        // Service check - every minute
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = self6.check_services().await {
                    tracing::error!("Service check failed: {}", e);
                }
            }
        });

        tracing::info!("Monitoring service started");
    }

    /// Refresh SMART cache for enabled disks
    async fn refresh_smart_cache(&self) {
        use crate::commands::filesystem;
        use crate::services::smart_cache::DiskRefreshInfo;

        let settings = self.state_manager.get_settings().await;
        let enabled_configs: Vec<_> = settings
            .smart_configs
            .iter()
            .filter(|c| c.enabled)
            .cloned()
            .collect();

        if enabled_configs.is_empty() {
            return;
        }

        let block_devices = match filesystem::list_block_devices().await {
            Ok(devices) => devices,
            Err(e) => {
                tracing::error!("Failed to list block devices for SMART refresh: {}", e);
                return;
            }
        };

        let disks: Vec<DiskRefreshInfo> = enabled_configs
            .iter()
            .filter_map(|cfg| {
                block_devices
                    .iter()
                    .find(|d| d.name == cfg.disk_name)
                    .map(|dev| DiskRefreshInfo {
                        name: cfg.disk_name.clone(),
                        path: dev.path.clone(),
                        size: dev.size,
                        power_mode: cfg.power_mode.clone(),
                    })
            })
            .collect();

        if disks.is_empty() {
            return;
        }

        self.smart_cache.refresh_with_config(&disks).await;
    }

    /// Get notification service if enabled
    async fn get_notifier(&self) -> Option<NotificationService> {
        let state = self.state_manager.get().await;
        let settings = self.state_manager.get_settings().await;

        if state.notifications.enabled {
            Some(NotificationService::new(
                state.notifications.clone(),
                settings.hostname,
            ))
        } else {
            None
        }
    }

    /// Check disk space usage
    async fn check_disk_space(&self) -> Result<(), String> {
        let notifier = match self.get_notifier().await {
            Some(n) => n,
            None => return Ok(()),
        };

        let state = self.state_manager.get().await;
        if !state.notifications.events.disk_space_warning
            && !state.notifications.events.disk_space_critical
        {
            return Ok(());
        }

        let usage = filesystem::get_usage().await.map_err(|e| e.to_string())?;

        for fs in usage {
            // Skip small/system filesystems
            if fs.size < 1_000_000_000 {
                // < 1GB
                continue;
            }

            let usage_percent = fs.use_percent;
            let mountpoint = &fs.mountpoint;

            let mut sent = self.sent_alerts.write().await;

            if usage_percent >= 95 && state.notifications.events.disk_space_critical {
                if !sent.disk_space.contains(mountpoint) {
                    tracing::warn!("Disk space CRITICAL on {}: {}%", mountpoint, usage_percent);
                    let _ = notifier
                        .send(
                            &format!("CRITICAL: Disk space on {}", mountpoint),
                            &format!(
                                "Disk space is critically low!\n\n\
                             Mount point: {}\n\
                             Usage: {}%\n\
                             Available: {} bytes\n\n\
                             Immediate action required!",
                                mountpoint, usage_percent, fs.available
                            ),
                        )
                        .await;
                    sent.disk_space.insert(mountpoint.clone());
                }
            } else if usage_percent >= 80 && state.notifications.events.disk_space_warning {
                if !sent.disk_space.contains(mountpoint) {
                    tracing::warn!("Disk space WARNING on {}: {}%", mountpoint, usage_percent);
                    let _ = notifier
                        .send(
                            &format!("WARNING: Disk space low on {}", mountpoint),
                            &format!(
                                "Disk space is running low.\n\n\
                             Mount point: {}\n\
                             Usage: {}%\n\
                             Available: {} bytes\n\n\
                             Please free up some space.",
                                mountpoint, usage_percent, fs.available
                            ),
                        )
                        .await;
                    sent.disk_space.insert(mountpoint.clone());
                }
            } else if usage_percent < 75 {
                sent.disk_space.remove(mountpoint);
            }
        }

        Ok(())
    }

    /// Check SMART status (only for enabled disks)
    async fn check_smart(&self) -> Result<(), String> {
        let notifier = match self.get_notifier().await {
            Some(n) => n,
            None => return Ok(()),
        };

        let state = self.state_manager.get().await;
        if !state.notifications.events.smart_errors {
            return Ok(());
        }

        let settings = self.state_manager.get_settings().await;
        let enabled_configs: Vec<_> = settings
            .smart_configs
            .iter()
            .filter(|c| c.enabled)
            .collect();

        if enabled_configs.is_empty() {
            return Ok(()); // No disks have SMART monitoring enabled
        }

        let block_devices = filesystem::list_block_devices()
            .await
            .map_err(|e| e.to_string())?;

        for dev in block_devices.iter().filter(|d| d.device_type == "disk") {
            let config = match enabled_configs.iter().find(|c| c.disk_name == dev.name) {
                Some(c) => c,
                None => continue, // Not configured for monitoring
            };

            let info = match smart::get_info_with_powermode(&dev.path, &config.power_mode).await {
                Ok(info) => info,
                Err(_) => continue, // Disk in power-saving mode or error
            };

            if info.smart_supported && !info.health_passed {
                let mut sent = self.sent_alerts.write().await;
                if !sent.smart_errors.contains(&dev.name) {
                    tracing::error!("SMART failure detected on {}", dev.name);
                    let _ = notifier
                        .send(
                            &format!("SMART FAILURE: {}", dev.name),
                            &format!(
                                "SMART health check FAILED for disk {}!\n\n\
                             Device: {}\n\
                             Model: {}\n\
                             Serial: {}\n\n\
                             This disk may be failing. Backup data immediately!",
                                dev.name, dev.path, info.model, info.serial
                            ),
                        )
                        .await;
                    sent.smart_errors.insert(dev.name.clone());
                }
            }
        }

        Ok(())
    }

    /// Check ZFS pool status
    async fn check_zfs(&self) -> Result<(), String> {
        if !zfs::is_available().await {
            return Ok(());
        }

        let notifier = match self.get_notifier().await {
            Some(n) => n,
            None => return Ok(()),
        };

        let state = self.state_manager.get().await;
        if !state.notifications.events.zfs_pool_errors {
            return Ok(());
        }

        let pools = zfs::list_pools().await.map_err(|e| e.to_string())?;

        for pool in pools {
            let health = pool.health.to_uppercase();
            let is_healthy = health == "ONLINE";

            let mut sent = self.sent_alerts.write().await;

            if !is_healthy {
                if !sent.zfs_errors.contains(&pool.name) {
                    tracing::error!("ZFS pool {} is {}", pool.name, health);
                    let _ = notifier
                        .send(
                            &format!("ZFS POOL {}: {}", health, pool.name),
                            &format!(
                                "ZFS pool '{}' is not healthy!\n\n\
                             Status: {}\n\
                             Size: {} bytes\n\
                             Used: {} bytes\n\n\
                             Run 'zpool status {}' for details.",
                                pool.name, health, pool.size, pool.allocated, pool.name
                            ),
                        )
                        .await;
                    sent.zfs_errors.insert(pool.name.clone());
                }
            } else if sent.zfs_errors.remove(&pool.name) {
                tracing::info!("ZFS pool {} recovered to ONLINE", pool.name);
                let _ = notifier
                    .send(
                        &format!("ZFS POOL RECOVERED: {}", pool.name),
                        &format!("ZFS pool '{}' is back ONLINE.", pool.name),
                    )
                    .await;
            }
        }

        Ok(())
    }

    /// Check disk temperatures (only for disks with SMART monitoring enabled)
    async fn check_temperatures(&self) -> Result<(), String> {
        let notifier = match self.get_notifier().await {
            Some(n) => n,
            None => return Ok(()),
        };

        let state = self.state_manager.get().await;
        if !state.notifications.events.high_temperature {
            return Ok(());
        }

        let settings = self.state_manager.get_settings().await;
        let enabled_configs: Vec<_> = settings
            .smart_configs
            .iter()
            .filter(|c| c.enabled)
            .collect();

        if enabled_configs.is_empty() {
            return Ok(()); // No disks have SMART monitoring enabled
        }

        let block_devices = filesystem::list_block_devices()
            .await
            .map_err(|e| e.to_string())?;

        for dev in block_devices.iter().filter(|d| d.device_type == "disk") {
            let config = match enabled_configs.iter().find(|c| c.disk_name == dev.name) {
                Some(c) => c,
                None => continue,
            };

            let info = match smart::get_info_with_powermode(&dev.path, &config.power_mode).await {
                Ok(info) => info,
                Err(_) => continue,
            };

            if let Some(temp) = info.temperature {
                let mut sent = self.sent_alerts.write().await;

                if temp >= config.temp_max {
                    if !sent.high_temp.contains(&dev.name) {
                        tracing::error!(
                            "Temperature threshold exceeded on {}: {}°C (max: {}°C)",
                            dev.name,
                            temp,
                            config.temp_max
                        );
                        let _ = notifier
                            .send(
                                &format!("🌡️ ALERT: {} at {}°C", dev.name, temp),
                                &format!(
                                    "Disk temperature exceeded threshold!\n\n\
                                     Device: {}\n\
                                     Temperature: {}°C\n\
                                     Threshold: {}°C\n\n\
                                     Check cooling immediately!",
                                    dev.name, temp, config.temp_max
                                ),
                            )
                            .await;
                        sent.high_temp.insert(dev.name.clone());
                    }
                } else if temp < config.temp_max - 5 {
                    // Clear alert if temp dropped below threshold - 5°C
                    sent.high_temp.remove(&dev.name);
                }

                if let Some(diff_threshold) = config.temp_difference {
                    if let Some(last_temp) = config.last_temp {
                        let diff = (temp - last_temp).abs();
                        if diff >= diff_threshold {
                            let alert_key = format!("{}_diff", dev.name);
                            if !sent.high_temp.contains(&alert_key) {
                                tracing::warn!(
                                    "Temperature change on {}: {}°C → {}°C (diff: {}°C)",
                                    dev.name,
                                    last_temp,
                                    temp,
                                    diff
                                );
                                let _ = notifier
                                    .send(
                                        &format!(
                                            "🌡️ Temperature change: {} ({}°C)",
                                            dev.name, diff
                                        ),
                                        &format!(
                                            "Significant temperature change detected!\n\n\
                                             Device: {}\n\
                                             Previous: {}°C\n\
                                             Current: {}°C\n\
                                             Change: {}°C",
                                            dev.name, last_temp, temp, diff
                                        ),
                                    )
                                    .await;
                                sent.high_temp.insert(alert_key);
                            }
                        }
                    }

                    let _ = self
                        .state_manager
                        .update(|s| {
                            if let Some(cfg) = s
                                .settings
                                .smart_configs
                                .iter_mut()
                                .find(|c| c.disk_name == dev.name)
                            {
                                cfg.last_temp = Some(temp);
                            }
                        })
                        .await;
                }
            }
        }

        Ok(())
    }

    /// Check critical services
    async fn check_services(&self) -> Result<(), String> {
        let notifier = match self.get_notifier().await {
            Some(n) => n,
            None => return Ok(()),
        };

        let state = self.state_manager.get().await;
        if !state.notifications.events.service_failures {
            return Ok(());
        }

        let mut services_to_check = Vec::new();

        if state.smb.enabled {
            services_to_check.push(("samba-smbd", "Samba/SMB"));
        }
        if state.nfs.enabled {
            services_to_check.push(("nfs-server", "NFS Server"));
        }
        if state.settings.ssh_enabled {
            services_to_check.push(("sshd", "SSH"));
        }
        if state.settings.rsync_enabled {
            services_to_check.push(("rsyncd", "Rsync"));
        }

        for (service, name) in services_to_check {
            let output = tokio::process::Command::new("systemctl")
                .args(["is-active", service])
                .output()
                .await;

            let is_active = output
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
                .unwrap_or(false);

            let mut sent = self.sent_alerts.write().await;

            if !is_active {
                if !sent.service_failures.contains(service) {
                    tracing::error!("Service {} ({}) is not running", name, service);
                    let _ = notifier
                        .send(
                            &format!("SERVICE DOWN: {}", name),
                            &format!(
                                "Service '{}' is not running!\n\n\
                             Service: {}\n\n\
                             Check with: systemctl status {}",
                                name, service, service
                            ),
                        )
                        .await;
                    sent.service_failures.insert(service.to_string());
                }
            } else if sent.service_failures.remove(service) {
                tracing::info!("Service {} recovered", name);
                let _ = notifier
                    .send(
                        &format!("SERVICE RECOVERED: {}", name),
                        &format!("Service '{}' is running again.", name),
                    )
                    .await;
            }
        }

        Ok(())
    }
}
