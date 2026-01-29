use crate::error::{RpcError, RpcResult, StateError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Maximum number of backup versions to keep
const MAX_BACKUPS: usize = 10;

/// Thread-safe state manager.
pub struct StateManager {
    path: PathBuf,
    state: RwLock<NasState>,
}

impl StateManager {
    /// Load state from file or create default.
    pub async fn load(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let path = path.as_ref().to_path_buf();

        let state = if path.exists() {
            let content = fs::read_to_string(&path)
                .await
                .map_err(|e| StateError::Read(e.to_string()))?;

            serde_json::from_str(&content).map_err(|e| StateError::Parse(e.to_string()))?
        } else {
            NasState::default()
        };

        Ok(Self {
            path,
            state: RwLock::new(state),
        })
    }

    /// Save current state to file with atomic write and backup.
    pub async fn save(&self) -> Result<(), StateError> {
        let state = self.state.read().await;
        let content =
            serde_json::to_string_pretty(&*state).map_err(|e| StateError::Parse(e.to_string()))?;

        // Create backup before modifying (if file exists)
        if self.path.exists()
            && let Err(e) = self.create_backup().await
        {
            tracing::warn!("Failed to create backup: {}", e);
            // Continue anyway - backup failure shouldn't block save
        }

        // Atomic write: write to temp file, then rename
        let tmp_path = self.path.with_extension("json.tmp");

        fs::write(&tmp_path, &content)
            .await
            .map_err(|e| StateError::Write(format!("Failed to write temp file: {}", e)))?;

        fs::rename(&tmp_path, &self.path)
            .await
            .map_err(|e| StateError::Write(format!("Failed to rename temp file: {}", e)))?;

        tracing::debug!("State saved successfully to {:?}", self.path);
        Ok(())
    }

    /// Create a timestamped backup of the current state file.
    async fn create_backup(&self) -> Result<(), StateError> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = self.path.with_extension(format!("json.{}", timestamp));

        fs::copy(&self.path, &backup_path)
            .await
            .map_err(|e| StateError::Write(format!("Failed to create backup: {}", e)))?;

        tracing::debug!("Created backup: {:?}", backup_path);

        self.cleanup_old_backups().await;

        Ok(())
    }

    /// Remove old backups, keeping only MAX_BACKUPS most recent.
    async fn cleanup_old_backups(&self) {
        let parent = match self.path.parent() {
            Some(p) => p,
            None => return,
        };

        let stem = match self.path.file_stem() {
            Some(s) => s.to_string_lossy().to_string(),
            None => return,
        };

        let mut backups: Vec<PathBuf> = Vec::new();

        if let Ok(mut entries) = fs::read_dir(parent).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with(&format!("{}.json.", stem))
                        && !name_str.ends_with(".tmp")
                        && name_str.len() > stem.len() + 6
                    {
                        backups.push(path);
                    }
                }
            }
        }

        backups.sort_by(|a, b| b.cmp(a));

        for old_backup in backups.into_iter().skip(MAX_BACKUPS) {
            if let Err(e) = fs::remove_file(&old_backup).await {
                tracing::warn!("Failed to remove old backup {:?}: {}", old_backup, e);
            } else {
                tracing::debug!("Removed old backup: {:?}", old_backup);
            }
        }
    }

    /// List available backups (most recent first).
    pub async fn list_backups(&self) -> Vec<PathBuf> {
        let parent = match self.path.parent() {
            Some(p) => p,
            None => return Vec::new(),
        };

        let stem = match self.path.file_stem() {
            Some(s) => s.to_string_lossy().to_string(),
            None => return Vec::new(),
        };

        let mut backups: Vec<PathBuf> = Vec::new();

        if let Ok(mut entries) = fs::read_dir(parent).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with(&format!("{}.json.", stem))
                        && !name_str.ends_with(".tmp")
                    {
                        backups.push(path);
                    }
                }
            }
        }

        backups.sort_by(|a, b| b.cmp(a));
        backups
    }

    /// Restore state from a backup file.
    pub async fn restore_backup(&self, backup_path: &Path) -> Result<(), StateError> {
        if !backup_path.exists() {
            return Err(StateError::Read("Backup file not found".to_string()));
        }

        let content = fs::read_to_string(backup_path)
            .await
            .map_err(|e| StateError::Read(e.to_string()))?;

        let restored_state: NasState = serde_json::from_str(&content)
            .map_err(|e| StateError::Parse(format!("Invalid backup: {}", e)))?;

        // Create backup of current state before restoring
        if self.path.exists() {
            self.create_backup().await?;
        }

        // Update in-memory state
        {
            let mut state = self.state.write().await;
            *state = restored_state;
        }

        self.save().await?;

        tracing::info!("Restored state from backup: {:?}", backup_path);
        Ok(())
    }

    /// Get a clone of the current state.
    pub async fn get(&self) -> NasState {
        self.state.read().await.clone()
    }

    /// Update state with a function and save.
    pub async fn update<F>(&self, f: F) -> Result<(), StateError>
    where
        F: FnOnce(&mut NasState),
    {
        {
            let mut state = self.state.write().await;
            f(&mut state);
        }
        self.save().await
    }

    pub async fn get_auth(&self) -> AuthConfig {
        self.state.read().await.auth.clone()
    }

    pub async fn set_auth(&self, auth: AuthConfig) -> Result<(), StateError> {
        self.update(|s| s.auth = auth).await
    }

    pub async fn get_settings(&self) -> NasSettings {
        self.state.read().await.settings.clone()
    }

    pub async fn set_hostname(&self, hostname: String) -> Result<(), StateError> {
        self.update(|s| {
            s.settings.hostname = hostname;
            s.pending_changes = true;
        })
        .await
    }

    pub async fn get_smb(&self) -> SmbConfig {
        self.state.read().await.smb.clone()
    }

    pub async fn set_smb_enabled(&self, enabled: bool) -> Result<(), StateError> {
        self.update(|s| {
            s.smb.enabled = enabled;
            s.pending_changes = true;
        })
        .await
    }

    pub async fn set_smb_settings(
        &self,
        workgroup: String,
        server_string: String,
    ) -> Result<(), StateError> {
        self.update(|s| {
            s.smb.workgroup = workgroup;
            s.smb.server_string = server_string;
            s.pending_changes = true;
        })
        .await
    }

    pub async fn add_smb_share(&self, share: SmbShare) -> RpcResult<Uuid> {
        let id = share.id;
        let mut state = self.state.write().await;

        if state.smb.shares.iter().any(|s| s.name == share.name) {
            return Err(RpcError::State(StateError::AlreadyExists(format!(
                "SMB share '{}'",
                share.name
            ))));
        }

        state.smb.shares.push(share);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(id)
    }

    pub async fn update_smb_share(&self, share: SmbShare) -> RpcResult<()> {
        let mut state = self.state.write().await;

        let pos = state
            .smb
            .shares
            .iter()
            .position(|s| s.id == share.id)
            .ok_or_else(|| {
                RpcError::State(StateError::NotFound(format!("SMB share {}", share.id)))
            })?;

        state.smb.shares[pos] = share;
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(())
    }

    pub async fn delete_smb_share(&self, id: Uuid) -> RpcResult<()> {
        let mut state = self.state.write().await;

        let pos = state
            .smb
            .shares
            .iter()
            .position(|s| s.id == id)
            .ok_or_else(|| RpcError::State(StateError::NotFound(format!("SMB share {}", id))))?;

        state.smb.shares.remove(pos);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(())
    }

    pub async fn get_samba_users(&self) -> Vec<SambaUser> {
        self.state.read().await.smb.users.clone()
    }

    pub async fn add_samba_user(&self, user: SambaUser) -> RpcResult<Uuid> {
        let id = user.id;
        let mut state = self.state.write().await;

        if state.smb.users.iter().any(|u| u.username == user.username) {
            return Err(RpcError::State(StateError::AlreadyExists(format!(
                "Samba user '{}'",
                user.username
            ))));
        }

        state.smb.users.push(user);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(id)
    }

    pub async fn update_samba_user(&self, user: SambaUser) -> RpcResult<()> {
        let mut state = self.state.write().await;

        let pos = state
            .smb
            .users
            .iter()
            .position(|u| u.id == user.id)
            .ok_or_else(|| {
                RpcError::State(StateError::NotFound(format!("Samba user {}", user.id)))
            })?;

        state.smb.users[pos] = user;
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(())
    }

    pub async fn delete_samba_user(&self, id: Uuid) -> RpcResult<String> {
        let mut state = self.state.write().await;

        let pos = state
            .smb
            .users
            .iter()
            .position(|u| u.id == id)
            .ok_or_else(|| RpcError::State(StateError::NotFound(format!("Samba user {}", id))))?;

        let username = state.smb.users[pos].username.clone();
        state.smb.users.remove(pos);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(username)
    }

    pub async fn set_samba_user_password_set(&self, id: Uuid, set: bool) -> RpcResult<()> {
        let mut state = self.state.write().await;

        let user = state
            .smb
            .users
            .iter_mut()
            .find(|u| u.id == id)
            .ok_or_else(|| RpcError::State(StateError::NotFound(format!("Samba user {}", id))))?;

        user.password_set = set;
        drop(state);
        self.save().await?;
        Ok(())
    }

    pub async fn get_nfs(&self) -> NfsConfig {
        self.state.read().await.nfs.clone()
    }

    pub async fn set_nfs_enabled(&self, enabled: bool) -> Result<(), StateError> {
        self.update(|s| {
            s.nfs.enabled = enabled;
            s.pending_changes = true;
        })
        .await
    }

    pub async fn add_nfs_export(&self, export: NfsExport) -> RpcResult<Uuid> {
        let id = export.id;
        let mut state = self.state.write().await;

        if state.nfs.exports.iter().any(|e| e.path == export.path) {
            return Err(RpcError::State(StateError::AlreadyExists(format!(
                "NFS export '{}'",
                export.path
            ))));
        }

        state.nfs.exports.push(export);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(id)
    }

    pub async fn update_nfs_export(&self, export: NfsExport) -> RpcResult<()> {
        let mut state = self.state.write().await;

        let pos = state
            .nfs
            .exports
            .iter()
            .position(|e| e.id == export.id)
            .ok_or_else(|| {
                RpcError::State(StateError::NotFound(format!("NFS export {}", export.id)))
            })?;

        state.nfs.exports[pos] = export;
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(())
    }

    pub async fn delete_nfs_export(&self, id: Uuid) -> RpcResult<()> {
        let mut state = self.state.write().await;

        let pos = state
            .nfs
            .exports
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| RpcError::State(StateError::NotFound(format!("NFS export {}", id))))?;

        state.nfs.exports.remove(pos);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_mounts(&self) -> Vec<PersistentMount> {
        self.state.read().await.mounts.clone()
    }

    #[allow(dead_code)]
    pub async fn add_mount(&self, mount: PersistentMount) -> RpcResult<Uuid> {
        let id = mount.id;
        let mut state = self.state.write().await;

        if state.mounts.iter().any(|m| m.path == mount.path) {
            return Err(RpcError::State(StateError::AlreadyExists(format!(
                "Mount point '{}'",
                mount.path
            ))));
        }

        state.mounts.push(mount);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(id)
    }

    #[allow(dead_code)]
    pub async fn delete_mount(&self, id: Uuid) -> RpcResult<()> {
        let mut state = self.state.write().await;

        let pos = state
            .mounts
            .iter()
            .position(|m| m.id == id)
            .ok_or_else(|| RpcError::State(StateError::NotFound(format!("Mount {}", id))))?;

        state.mounts.remove(pos);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_zfs_pools(&self) -> Vec<String> {
        self.state.read().await.zfs_pools.clone()
    }

    #[allow(dead_code)]
    pub async fn add_zfs_pool(&self, name: String) -> Result<(), StateError> {
        self.update(|s| {
            if !s.zfs_pools.contains(&name) {
                s.zfs_pools.push(name);
                s.pending_changes = true;
            }
        })
        .await
    }

    #[allow(dead_code)]
    pub async fn remove_zfs_pool(&self, name: &str) -> Result<(), StateError> {
        self.update(|s| {
            s.zfs_pools.retain(|p| p != name);
            s.pending_changes = true;
        })
        .await
    }

    pub async fn has_pending_changes(&self) -> bool {
        self.state.read().await.pending_changes
    }

    #[allow(dead_code)]
    pub async fn mark_pending(&self) -> Result<(), StateError> {
        self.update(|s| s.pending_changes = true).await
    }

    pub async fn clear_pending(&self) -> Result<(), StateError> {
        self.update(|s| s.pending_changes = false).await
    }

    pub async fn get_snapshot_policies(&self) -> Vec<SnapshotPolicy> {
        self.state.read().await.snapshot_policies.clone()
    }

    pub async fn add_snapshot_policy(&self, policy: SnapshotPolicy) -> RpcResult<Uuid> {
        let id = policy.id;
        let mut state = self.state.write().await;

        if state
            .snapshot_policies
            .iter()
            .any(|p| p.name == policy.name)
        {
            return Err(RpcError::State(StateError::AlreadyExists(format!(
                "Snapshot policy '{}'",
                policy.name
            ))));
        }

        state.snapshot_policies.push(policy);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(id)
    }

    pub async fn update_snapshot_policy(&self, policy: SnapshotPolicy) -> RpcResult<()> {
        let mut state = self.state.write().await;

        let pos = state
            .snapshot_policies
            .iter()
            .position(|p| p.id == policy.id)
            .ok_or_else(|| {
                RpcError::State(StateError::NotFound(format!(
                    "Snapshot policy {}",
                    policy.id
                )))
            })?;

        state.snapshot_policies[pos] = policy;
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(())
    }

    pub async fn delete_snapshot_policy(&self, id: Uuid) -> RpcResult<()> {
        let mut state = self.state.write().await;

        let pos = state
            .snapshot_policies
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| {
                RpcError::State(StateError::NotFound(format!("Snapshot policy {}", id)))
            })?;

        state.snapshot_policies.remove(pos);
        state.pending_changes = true;
        drop(state);
        self.save().await?;
        Ok(())
    }
}

/// Root state structure persisted to state.json.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NasState {
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub settings: NasSettings,
    #[serde(default)]
    pub smb: SmbConfig,
    #[serde(default)]
    pub nfs: NfsConfig,
    #[serde(default)]
    pub mounts: Vec<PersistentMount>,
    #[serde(default)]
    pub zfs_pools: Vec<String>,
    #[serde(default)]
    pub zfs_settings: ZfsSettings,
    #[serde(default)]
    pub snapshot_policies: Vec<SnapshotPolicy>,
    /// System users (Unix users)
    #[serde(default)]
    pub system_users: Vec<SystemUser>,
    /// System groups (Unix groups)
    #[serde(default)]
    pub system_groups: Vec<SystemGroup>,
    /// Home directories configuration
    #[serde(default)]
    pub home_directories: HomeDirectoriesConfig,
    /// Rsync modules
    #[serde(default)]
    pub rsync_modules: Vec<RsyncModule>,
    /// Email notification settings
    #[serde(default)]
    pub notifications: NotificationConfig,
    /// Pending Samba passwords to set after apply (username, password)
    #[serde(skip)]
    pub pending_samba_passwords: Vec<(String, String)>,
    /// True when configuration has changed but not yet applied
    #[serde(default)]
    pub pending_changes: bool,
}

/// General NAS settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NasSettings {
    /// Hostname / network name of the NAS
    #[serde(default = "default_hostname")]
    pub hostname: String,

    #[serde(default = "default_true")]
    pub ssh_enabled: bool,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default)]
    pub ssh_permit_root_login: bool,
    #[serde(default = "default_true")]
    pub ssh_password_auth: bool,
    #[serde(default = "default_true")]
    pub ssh_pubkey_auth: bool,

    #[serde(default)]
    pub rsync_enabled: bool,

    #[serde(default)]
    pub smart_configs: Vec<SmartDiskConfig>,

    #[serde(default)]
    pub disk_slots: Vec<DiskSlot>,
}

/// Physical disk slot mapping (like NetApp disk shelf)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSlot {
    /// Slot identifier (e.g., "1", "2", "A1", "Bay 1")
    pub slot: String,
    /// Disk identifier - by-id path preferred (e.g., "/dev/disk/by-id/ata-WDC_...")
    pub disk_id: String,
    /// Optional label/description (e.g., "Top left", "Backplane 1")
    #[serde(default)]
    pub label: String,
}

/// SMART monitoring configuration for a single disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartDiskConfig {
    /// Disk name (e.g., "sda", "nvme0n1")
    pub disk_name: String,

    /// Whether SMART monitoring is enabled for this disk
    #[serde(default)]
    pub enabled: bool,

    /// Check interval in seconds (default: 1800 = 30 minutes)
    #[serde(default = "default_smart_interval")]
    pub check_interval: u32,

    /// Power mode for checking
    #[serde(default)]
    pub power_mode: SmartPowerMode,

    /// Temperature difference threshold (None = disabled)
    /// Notify if temperature changed by N degrees since last check
    #[serde(default)]
    pub temp_difference: Option<i32>,

    /// Maximum temperature threshold in °C (default: 60)
    #[serde(default = "default_temp_max")]
    pub temp_max: i32,

    /// Last recorded temperature (for difference calculation)
    #[serde(default)]
    pub last_temp: Option<i32>,
}

fn default_smart_interval() -> u32 {
    1800 // 30 minutes
}

fn default_temp_max() -> i32 {
    60
}

/// Power mode for SMART checks
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SmartPowerMode {
    /// Never - check device regardless of power state (may spin up disk)
    Never,
    /// Sleep - check if device is not in sleep mode
    Sleep,
    /// Standby - check if device is not in sleep or standby mode (default, recommended)
    #[default]
    Standby,
    /// Idle - check if device is not in sleep, standby, or idle mode
    Idle,
}

#[allow(dead_code)]
impl SmartPowerMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SmartPowerMode::Never => "never",
            SmartPowerMode::Sleep => "sleep",
            SmartPowerMode::Standby => "standby",
            SmartPowerMode::Idle => "idle",
        }
    }

    pub fn smartctl_flag(&self) -> Option<&'static str> {
        match self {
            SmartPowerMode::Never => None,
            SmartPowerMode::Sleep => Some("-n sleep"),
            SmartPowerMode::Standby => Some("-n standby"),
            SmartPowerMode::Idle => Some("-n idle"),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            SmartPowerMode::Never => "Never - check disk regardless of power state",
            SmartPowerMode::Sleep => "Sleep - check if disk is not in sleep mode",
            SmartPowerMode::Standby => "Standby - check if disk is not in standby (recommended)",
            SmartPowerMode::Idle => "Idle - check if disk is not idle",
        }
    }
}

impl Default for SmartDiskConfig {
    fn default() -> Self {
        Self {
            disk_name: String::new(),
            enabled: false,
            check_interval: default_smart_interval(),
            power_mode: SmartPowerMode::default(),
            temp_difference: None,
            temp_max: default_temp_max(),
            last_temp: None,
        }
    }
}

fn default_ssh_port() -> u16 {
    22
}

fn default_hostname() -> String {
    "nixnas".to_string()
}

impl Default for NasSettings {
    fn default() -> Self {
        Self {
            hostname: default_hostname(),
            ssh_enabled: true,
            ssh_port: default_ssh_port(),
            ssh_permit_root_login: false,
            ssh_password_auth: true,
            ssh_pubkey_auth: true,
            rsync_enabled: false,
            smart_configs: Vec::new(),
            disk_slots: Vec::new(),
        }
    }
}

/// Rsync module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsyncModule {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default = "default_rsync_uid")]
    pub uid: String,
    #[serde(default = "default_rsync_gid")]
    pub gid: String,
    #[serde(default = "default_true")]
    pub use_chroot: bool,
    #[serde(default)]
    pub auth_users: bool,
    #[serde(default = "default_true")]
    pub read_only: bool,
    #[serde(default)]
    pub write_only: bool,
    #[serde(default = "default_true")]
    pub list: bool,
    #[serde(default)]
    pub max_connections: u32,
    #[serde(default)]
    pub hosts_allow: String,
    #[serde(default)]
    pub hosts_deny: String,
    #[serde(default)]
    pub extra_options: String,
}

fn default_rsync_uid() -> String {
    "nobody".to_string()
}

fn default_rsync_gid() -> String {
    "nogroup".to_string()
}

impl RsyncModule {
    #[allow(dead_code)]
    pub fn new(name: String, path: String) -> Self {
        Self {
            name,
            path,
            comment: String::new(),
            uid: default_rsync_uid(),
            gid: default_rsync_gid(),
            use_chroot: true,
            auth_users: false,
            read_only: true,
            write_only: false,
            list: true,
            max_connections: 0,
            hosts_allow: String::new(),
            hosts_deny: String::new(),
            extra_options: String::new(),
        }
    }
}

/// ZFS service settings (scrub, trim, import).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZfsSettings {
    /// Enable automatic scrubbing
    #[serde(default)]
    pub auto_scrub_enable: bool,
    /// Pools to scrub (empty = all pools)
    #[serde(default)]
    pub auto_scrub_pools: Vec<String>,
    /// Scrub interval (e.g., "weekly", "monthly", "Mon *-*-* 02:00:00")
    #[serde(default = "default_scrub_interval")]
    pub auto_scrub_interval: String,
    /// Enable automatic TRIM (for SSDs)
    #[serde(default = "default_trim_enable")]
    pub trim_enable: bool,
    /// TRIM interval (e.g., "weekly", "daily")
    #[serde(default = "default_trim_interval")]
    pub trim_interval: String,
    /// Extra pools to import at boot (beyond those with filesystems)
    #[serde(default)]
    pub extra_pools: Vec<String>,
    /// Force import of all pools (even if previously used by another system)
    #[serde(default)]
    pub force_import_all: bool,
    /// Device nodes path for pool discovery (for VMs: /dev/disk/by-path)
    #[serde(default)]
    pub dev_nodes: Option<String>,
    /// Maximum ARC size in GB (0 = auto/default)
    #[serde(default)]
    pub arc_max_gb: u32,
}

fn default_scrub_interval() -> String {
    "monthly".to_string()
}

fn default_trim_interval() -> String {
    "weekly".to_string()
}

fn default_trim_enable() -> bool {
    true
}

impl Default for ZfsSettings {
    fn default() -> Self {
        Self {
            auto_scrub_enable: false, // NixOS default: disabled
            auto_scrub_pools: Vec::new(),
            auto_scrub_interval: default_scrub_interval(),
            trim_enable: true, // NixOS default: enabled
            trim_interval: default_trim_interval(),
            extra_pools: Vec::new(),
            force_import_all: false,
            dev_nodes: None, // Use NixOS default
            arc_max_gb: 0,   // 0 = auto (use ZFS default)
        }
    }
}

/// ZFS snapshot policy for automatic snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPolicy {
    pub id: Uuid,
    pub name: String,
    pub dataset: String,
    pub recursive: bool,
    #[serde(default)]
    pub enabled: bool,
    /// Hourly snapshots to keep
    #[serde(default)]
    pub hourly: u32,
    /// Daily snapshots to keep
    #[serde(default)]
    pub daily: u32,
    /// Weekly snapshots to keep
    #[serde(default)]
    pub weekly: u32,
    /// Monthly snapshots to keep
    #[serde(default)]
    pub monthly: u32,
    /// Yearly snapshots to keep  
    #[serde(default)]
    pub yearly: u32,
}

impl SnapshotPolicy {
    #[allow(dead_code)]
    pub fn new(name: String, dataset: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            dataset,
            recursive: true,
            enabled: true,
            hourly: 24,
            daily: 7,
            weekly: 4,
            monthly: 12,
            yearly: 0,
        }
    }
}

/// Authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub admin_password_hash: String,
    pub jwt_secret: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            // Default password: "admin" - MUST be changed on first login
            admin_password_hash: String::new(),
            jwt_secret: Uuid::new_v4().to_string(),
        }
    }
}

/// Samba/SMB configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbConfig {
    pub enabled: bool,
    pub workgroup: String,
    pub server_string: String,
    #[serde(default)]
    pub shares: Vec<SmbShare>,
    #[serde(default)]
    pub users: Vec<SambaUser>,

    /// Minimum SMB protocol version (SMB2, SMB3, SMB3_00, SMB3_02, SMB3_11)
    #[serde(default = "default_min_protocol")]
    pub min_protocol: String,
    /// Disable NetBIOS (recommended for modern networks)
    #[serde(default = "default_true")]
    pub disable_netbios: bool,
    /// Enable WINS support
    #[serde(default)]
    pub wins_support: bool,
    /// WINS server address
    #[serde(default)]
    pub wins_server: String,
    /// Enable unix extensions
    #[serde(default = "default_true")]
    pub unix_extensions: bool,
    /// Use sendfile for better performance
    #[serde(default = "default_true")]
    pub use_sendfile: bool,
    /// Enable async I/O
    #[serde(default = "default_true")]
    pub aio_enabled: bool,
    /// Enable Apple Time Machine support
    #[serde(default)]
    pub time_machine_support: bool,
    /// Act as time server for Windows clients
    #[serde(default)]
    pub time_server: bool,
    /// Guest account name
    #[serde(default = "default_guest_account")]
    pub guest_account: String,
    /// Global create mask
    #[serde(default = "default_create_mask")]
    pub global_create_mask: String,
    /// Global directory mask
    #[serde(default = "default_directory_mask")]
    pub global_directory_mask: String,
    /// Log level (0-10)
    #[serde(default)]
    pub log_level: u8,
    /// Extra global options (raw smb.conf)
    #[serde(default)]
    pub extra_options: String,

    /// Enable home directories share
    #[serde(default)]
    pub homes_enabled: bool,
    /// Home directories browseable
    #[serde(default = "default_true")]
    pub homes_browseable: bool,
    /// Home directories inherit ACLs
    #[serde(default)]
    pub homes_inherit_acls: bool,
    /// Home directories inherit permissions
    #[serde(default)]
    pub homes_inherit_permissions: bool,
    /// Home directories recycle bin
    #[serde(default)]
    pub homes_recycle_bin: bool,
    /// Home directories follow symlinks
    #[serde(default)]
    pub homes_follow_symlinks: bool,
    /// Home directories wide links
    #[serde(default)]
    pub homes_wide_links: bool,
    /// Home directories extra options
    #[serde(default)]
    pub homes_extra_options: String,
}

fn default_min_protocol() -> String {
    "SMB2".to_string()
}

fn default_guest_account() -> String {
    "nobody".to_string()
}

impl Default for SmbConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            workgroup: "WORKGROUP".to_string(),
            server_string: "NixNAS".to_string(),
            shares: Vec::new(),
            users: Vec::new(),
            min_protocol: default_min_protocol(),
            disable_netbios: true,
            wins_support: false,
            wins_server: String::new(),
            unix_extensions: true,
            use_sendfile: true,
            aio_enabled: true,
            time_machine_support: false,
            time_server: false,
            guest_account: default_guest_account(),
            global_create_mask: default_create_mask(),
            global_directory_mask: default_directory_mask(),
            log_level: 0,
            extra_options: String::new(),
            homes_enabled: false,
            homes_browseable: true,
            homes_inherit_acls: false,
            homes_inherit_permissions: false,
            homes_recycle_bin: false,
            homes_follow_symlinks: false,
            homes_wide_links: false,
            homes_extra_options: String::new(),
        }
    }
}

/// Samba user for share access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SambaUser {
    pub id: Uuid,
    pub username: String,
    /// Hashed password (stored for reference, actual samba password set via smbpasswd)
    #[serde(default)]
    pub password_set: bool,
    /// Optional description
    #[serde(default)]
    pub description: String,
    /// Whether user is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Groups this user belongs to
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Share privilege level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
pub enum PrivilegeLevel {
    /// No access (0)
    #[default]
    NoAccess = 0,
    /// Read only (5)
    ReadOnly = 5,
    /// Read/Write (7)
    ReadWrite = 7,
}

/// User/Group privilege for a share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePrivilege {
    /// User or group name
    pub name: String,
    /// Is this a group? (false = user)
    #[serde(default)]
    pub is_group: bool,
    /// Permission level
    #[serde(default)]
    pub permission: PrivilegeLevel,
}

/// SMB share definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbShare {
    pub id: Uuid,
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default = "default_true")]
    pub browseable: bool,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub guest_ok: bool,
    /// Allow only guest access
    #[serde(default)]
    pub guest_only: bool,
    /// Users allowed to access this share (empty = all authenticated users)
    #[serde(default)]
    pub valid_users: Vec<String>,
    /// Users NOT allowed to access this share
    #[serde(default)]
    pub invalid_users: Vec<String>,
    /// Users with write access (even if read_only=true)
    #[serde(default)]
    pub write_list: Vec<String>,
    /// Users with read-only access (overrides write_list)
    #[serde(default)]
    pub read_list: Vec<String>,
    /// Force all file operations as this user
    #[serde(default)]
    pub force_user: Option<String>,
    /// Force all file operations as this group
    #[serde(default)]
    pub force_group: Option<String>,
    #[serde(default = "default_create_mask")]
    pub create_mask: String,
    #[serde(default = "default_directory_mask")]
    pub directory_mask: String,
    /// Force create mode (always set these bits)
    #[serde(default)]
    pub force_create_mode: Option<String>,
    /// Force directory mode (always set these bits)
    #[serde(default)]
    pub force_directory_mode: Option<String>,
    /// Inherit ACLs from parent directory
    #[serde(default)]
    pub inherit_acls: bool,
    /// Inherit permissions from parent directory
    #[serde(default)]
    pub inherit_permissions: bool,
    /// Enable extended attributes support
    #[serde(default = "default_true")]
    pub ea_support: bool,
    /// Store DOS attributes in extended attributes
    #[serde(default)]
    pub store_dos_attributes: bool,
    /// Hide dot files (Unix hidden files)
    #[serde(default = "default_true")]
    pub hide_dot_files: bool,
    /// Hide special files (sockets, devices, etc.)
    #[serde(default = "default_true")]
    pub hide_special_files: bool,
    /// Follow symbolic links
    #[serde(default = "default_true")]
    pub follow_symlinks: bool,
    /// Allow symlinks outside share (security risk!)
    #[serde(default)]
    pub wide_links: bool,
    /// VFS objects (e.g., "recycle", "full_audit")
    #[serde(default)]
    pub vfs_objects: Vec<String>,
    /// Time Machine target (macOS backup)
    #[serde(default)]
    pub time_machine: bool,

    /// Hosts allowed to access (space-separated IPs/hostnames)
    #[serde(default)]
    pub hosts_allow: Vec<String>,
    /// Hosts denied access (space-separated IPs/hostnames)
    #[serde(default)]
    pub hosts_deny: Vec<String>,
    /// Enable recycle bin
    #[serde(default)]
    pub recycle_bin: bool,
    /// Max file size for recycle bin (0 = no limit)
    #[serde(default)]
    pub recycle_max_size: u64,
    /// Retention days for recycle bin (0 = no auto-delete)
    #[serde(default)]
    pub recycle_retention_days: u32,
    /// Enable file audit logging
    #[serde(default)]
    pub audit_enabled: bool,
    /// SMB encryption mode: auto, desired, required, off
    #[serde(default = "default_smb_encrypt")]
    pub smb_encrypt: String,
    /// Extra options (raw smb.conf options)
    #[serde(default)]
    pub extra_options: String,
    /// User/Group privileges
    #[serde(default)]
    pub privileges: Vec<SharePrivilege>,
}

fn default_smb_encrypt() -> String {
    "auto".to_string()
}

fn default_true() -> bool {
    true
}

fn default_create_mask() -> String {
    "0664".to_string()
}

fn default_directory_mask() -> String {
    "0775".to_string()
}

impl SmbShare {
    pub fn new(name: String, path: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            path,
            comment: String::new(),
            browseable: true,
            read_only: false,
            guest_ok: false,
            guest_only: false,
            valid_users: Vec::new(),
            invalid_users: Vec::new(),
            write_list: Vec::new(),
            read_list: Vec::new(),
            force_user: None,
            force_group: None,
            create_mask: default_create_mask(),
            directory_mask: default_directory_mask(),
            force_create_mode: None,
            force_directory_mode: None,
            inherit_acls: false,
            inherit_permissions: false,
            ea_support: true,
            store_dos_attributes: false,
            hide_dot_files: true,
            hide_special_files: true,
            follow_symlinks: true,
            wide_links: false,
            vfs_objects: Vec::new(),
            time_machine: false,
            hosts_allow: Vec::new(),
            hosts_deny: Vec::new(),
            recycle_bin: false,
            recycle_max_size: 0,
            recycle_retention_days: 0,
            audit_enabled: false,
            smb_encrypt: default_smb_encrypt(),
            extra_options: String::new(),
            privileges: Vec::new(),
        }
    }
}

/// NFS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfsConfig {
    pub enabled: bool,
    #[serde(default)]
    pub exports: Vec<NfsExport>,
    #[serde(default = "default_nfs_versions")]
    pub versions: Vec<String>, // "3", "4", "4.1", "4.2"
    #[serde(default = "default_nfs_threads")]
    pub threads: u32,
}

fn default_nfs_versions() -> Vec<String> {
    vec![
        "3".to_string(),
        "4".to_string(),
        "4.1".to_string(),
        "4.2".to_string(),
    ]
}

fn default_nfs_threads() -> u32 {
    8
}

impl Default for NfsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            exports: Vec::new(),
            versions: default_nfs_versions(),
            threads: default_nfs_threads(),
        }
    }
}

/// NFS export definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfsExport {
    pub id: Uuid,
    pub path: String,
    pub clients: Vec<NfsClient>,
    /// Extra options (raw, comma-separated)
    #[serde(default)]
    pub extra_options: String,
}

impl NfsExport {
    #[allow(dead_code)]
    pub fn new(path: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            path,
            clients: Vec::new(),
            extra_options: String::new(),
        }
    }

    /// Generate exports file line for /etc/exports
    pub fn to_exports_line(&self) -> String {
        if self.clients.is_empty() {
            let mut opts = vec![
                "ro".to_string(),
                "sync".to_string(),
                "no_subtree_check".to_string(),
            ];
            if !self.extra_options.is_empty() {
                for opt in self.extra_options.split(',') {
                    let opt = opt.trim();
                    if !opt.is_empty() && !opts.contains(&opt.to_string()) {
                        opts.push(opt.to_string());
                    }
                }
            }
            return format!("{} *({})", self.path, opts.join(","));
        }

        let clients: Vec<String> = self
            .clients
            .iter()
            .map(|c| {
                let mut opts = c.options.clone();
                if !self.extra_options.is_empty() {
                    for opt in self.extra_options.split(',') {
                        let opt = opt.trim();
                        if !opt.is_empty() && !opts.contains(&opt.to_string()) {
                            opts.push(opt.to_string());
                        }
                    }
                }
                format!("{}({})", c.host, opts.join(","))
            })
            .collect();

        format!("{} {}", self.path, clients.join(" "))
    }
}

/// NFS client access rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfsClient {
    pub host: String,
    pub options: Vec<String>,
}

impl NfsClient {
    #[allow(dead_code)]
    pub fn new(host: String) -> Self {
        Self {
            host,
            options: vec![
                "rw".to_string(),
                "sync".to_string(),
                "no_subtree_check".to_string(),
            ],
        }
    }
}

/// Persistent mount point (for /etc/fstab via NixOS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentMount {
    pub id: Uuid,
    pub device: String,
    pub path: String,
    pub fstype: String,
    #[serde(default)]
    pub options: Vec<String>,
}

impl PersistentMount {
    #[allow(dead_code)]
    pub fn new(device: String, path: String, fstype: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            device,
            path,
            fstype,
            options: vec!["defaults".to_string()],
        }
    }
}

/// System user configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemUser {
    pub id: Uuid,
    pub username: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub shell: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub ssh_keys: Vec<String>,
    #[serde(default)]
    pub home_dir: Option<String>,
    #[serde(default)]
    pub create_home: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Has Samba (SMB) access
    #[serde(default)]
    pub samba_access: bool,
    /// Hashed password (SHA-512 format for NixOS)
    #[serde(default)]
    pub hashed_password: Option<String>,
    /// Is this user managed by NixOS (declarative)?
    #[serde(default = "default_true")]
    pub is_system_user: bool,
    /// UID (optional, let system assign if None)
    #[serde(default)]
    pub uid: Option<u32>,
}

impl SystemUser {
    pub fn new(username: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            username,
            description: String::new(),
            email: String::new(),
            shell: "/usr/bin/nologin".to_string(),
            groups: Vec::new(),
            ssh_keys: Vec::new(),
            home_dir: None,
            create_home: false,
            enabled: true,
            samba_access: true,
            hashed_password: None,
            is_system_user: false,
            uid: None,
        }
    }
}

/// System group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGroup {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub members: Vec<String>,
    /// GID (optional, let system assign if None)
    #[serde(default)]
    pub gid: Option<u32>,
}

impl SystemGroup {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description: String::new(),
            members: Vec::new(),
            gid: None,
        }
    }
}

/// User home directories configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HomeDirectoriesConfig {
    pub enabled: bool,
    /// Base path for home directories
    #[serde(default = "default_home_base")]
    pub base_path: String,
    /// Skeleton directory
    #[serde(default)]
    pub skel_path: Option<String>,
}

fn default_home_base() -> String {
    "/home".to_string()
}

/// Email notification configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub smtp: SmtpConfig,
    #[serde(default)]
    pub events: NotificationEvents,
}

/// SMTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    #[serde(default)]
    pub server: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default)]
    pub encryption: SmtpEncryption,
    #[serde(default)]
    pub sender: String,
    #[serde(default)]
    pub auth_required: bool,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub recipient: String,
    #[serde(default)]
    pub recipient_secondary: Option<String>,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: default_smtp_port(),
            encryption: SmtpEncryption::default(),
            sender: String::new(),
            auth_required: true,
            username: String::new(),
            password: String::new(),
            recipient: String::new(),
            recipient_secondary: None,
        }
    }
}

fn default_smtp_port() -> u16 {
    587
}

/// SMTP encryption mode
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub enum SmtpEncryption {
    None,
    #[default]
    StartTls,
    Ssl,
}

impl SmtpEncryption {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StartTls => "starttls",
            Self::Ssl => "ssl",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "none" => Self::None,
            "ssl" | "tls" => Self::Ssl,
            _ => Self::StartTls,
        }
    }
}

/// Which events trigger notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationEvents {
    #[serde(default = "default_true")]
    pub disk_space_warning: bool,
    #[serde(default = "default_true")]
    pub disk_space_critical: bool,
    #[serde(default = "default_true")]
    pub smart_errors: bool,
    #[serde(default = "default_true")]
    pub zfs_pool_errors: bool,
    #[serde(default)]
    pub zfs_scrub_complete: bool,
    #[serde(default = "default_true")]
    pub raid_errors: bool,
    #[serde(default = "default_true")]
    pub service_failures: bool,
    #[serde(default)]
    pub system_startup: bool,
    #[serde(default)]
    pub system_shutdown: bool,
    #[serde(default)]
    pub high_cpu_usage: bool,
    #[serde(default)]
    pub high_memory_usage: bool,
    #[serde(default = "default_true")]
    pub high_temperature: bool,
}

impl Default for NotificationEvents {
    fn default() -> Self {
        Self {
            disk_space_warning: true,
            disk_space_critical: true,
            smart_errors: true,
            zfs_pool_errors: true,
            zfs_scrub_complete: false,
            raid_errors: true,
            service_failures: true,
            system_startup: false,
            system_shutdown: false,
            high_cpu_usage: false,
            high_memory_usage: false,
            high_temperature: true,
        }
    }
}
