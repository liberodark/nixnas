use crate::auth::AuthManager;
use crate::commands::{btrfs, filesystem, mdadm, samba, smart, zfs};
use crate::nix::NixGenerator;
use crate::services::metrics::MetricsStore;
use crate::services::notifications::NotificationService;
use crate::services::{nfs::NfsService, smb::SmbService};
use crate::state::{
    NfsClient, NfsExport, NotificationConfig, NotificationEvents, PrivilegeLevel, RsyncModule,
    SambaUser, SharePrivilege, SmartDiskConfig, SmartPowerMode, SmbShare, SmtpConfig,
    SmtpEncryption, SnapshotPolicy, StateManager, SystemGroup, SystemUser, ZfsSettings,
};
use askama::Template;
use axum::{
    Form, Router,
    extract::{
        Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{delete, get, post, put},
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Embedded CSS stylesheet
const STYLESHEET: &str = include_str!("../static/style.css");
const PICO_CSS: &str = include_str!("../static/pico.min.css");
const HTMX_JS: &str = include_str!("../static/htmx.min.js");

pub struct WebState {
    pub state_manager: Arc<StateManager>,
    pub auth: Arc<AuthManager>,
    pub smb: Arc<SmbService>,
    pub nfs: Arc<NfsService>,
    pub nix: Arc<NixGenerator>,
    pub metrics: Arc<crate::services::metrics::MetricsStore>,
    pub smart_cache: Arc<crate::services::smart_cache::SmartCache>,
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    if bytes >= TIB {
        format!("{:.2} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn opt_to_string(opt: &Option<String>) -> String {
    opt.clone().unwrap_or_else(|| "—".to_string())
}

/// Create a share directory with permissions: root:users 2775
async fn create_share_directory(path: &str) -> Result<(), String> {
    use tokio::process::Command;

    if let Err(e) = tokio::fs::create_dir_all(path).await
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(format!("Failed to create directory {}: {}", path, e));
    }

    let _ = Command::new("chown")
        .args(["root:users", path])
        .output()
        .await;

    let _ = Command::new("chmod").args(["2775", path]).output().await;

    Ok(())
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    needs_setup: bool,
}

#[derive(Clone)]
struct SystemInfoView {
    hostname: String,
    kernel: String,
    arch: String,
    uptime: String,
    datetime: String,
    cpu_model: String,
    cpu_cores: usize,
    cpu_usage_percent: u8,
}

#[derive(Clone)]
struct MemoryInfoView {
    total: String,
    used: String,
    available: String,
    used_percent: u8,
    swap_total: String,
    swap_used: String,
    swap_percent: u8,
}

#[derive(Clone)]
struct LoadAvgView {
    load1: f64,
    load5: f64,
    load15: f64,
    load1_str: String,
    load5_str: String,
    load15_str: String,
}

#[derive(Clone)]
struct ServiceStatusView {
    name: String,
    active: bool,
}

#[derive(Clone)]
struct NetworkInterfaceView {
    name: String,
    ipv4: String,
    speed: String,
    is_up: bool,
}

#[derive(Clone)]
struct DiskTempView {
    name: String,
    temp: i32,
}

#[derive(Clone)]
struct SmartStatusView {
    name: String,
    status: String, // "ok", "warning", "failed"
}

#[derive(Clone)]
struct ZfsArcView {
    hits: String,
    misses: String,
    total: u64,
    hit_percent: u8,
    size: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    active_page: String,
    system_info: SystemInfoView,
    memory: MemoryInfoView,
    load_avg: LoadAvgView,
    services: Vec<ServiceStatusView>,
    network_interfaces: Vec<NetworkInterfaceView>,
    disk_temps: Vec<DiskTempView>,
    smart_status: Vec<SmartStatusView>,
    zfs_arc: ZfsArcView,
    disk_count: usize,
    smb_share_count: usize,
    nfs_export_count: usize,
    zfs_pool_count: usize,
    filesystems: Vec<FilesystemInfo>,
}

#[derive(Template)]
#[template(path = "storage/disks.html")]
struct DisksTemplate {
    active_page: String,
    disks: Vec<DiskInfo>,
    filesystems: Vec<FilesystemInfo>,
}

#[derive(Template)]
#[template(path = "storage/smart.html")]
struct SmartTemplate {
    active_page: String,
    smart_available: bool,
    disks: Vec<SmartDiskInfo>,
}

#[derive(Template)]
#[template(path = "storage/zfs.html")]
struct ZfsTemplate {
    active_page: String,
    zfs_available: bool,
    pools: Vec<PoolInfo>,
}

#[derive(Template)]
#[template(path = "storage/btrfs.html")]
struct BtrfsTemplate {
    active_page: String,
    btrfs_available: bool,
    filesystems: Vec<BtrfsInfo>,
}

#[derive(Template)]
#[template(path = "storage/raid.html")]
struct RaidTemplate {
    active_page: String,
    mdadm_available: bool,
    arrays: Vec<ArrayInfo>,
}

#[derive(Template)]
#[template(path = "shares/smb.html")]
struct SmbTemplate {
    active_page: String,
    smb_enabled: bool,
    shares: Vec<SmbShareView>,
}

#[derive(Template)]
#[template(path = "shares/smb_row.html")]
struct SmbRowTemplate {
    share: SmbShareView,
}

#[derive(Template)]
#[template(path = "shares/smb_edit.html")]
struct SmbEditTemplate {
    share: SmbShareView,
}

#[derive(Template)]
#[template(path = "shares/nfs.html")]
struct NfsTemplate {
    active_page: String,
    nfs_enabled: bool,
    exports: Vec<NfsExportView>,
}

#[derive(Template)]
#[template(path = "shares/nfs_row.html")]
struct NfsRowTemplate {
    export: NfsExportView,
}

#[derive(Template)]
#[template(path = "users/users.html")]
struct UsersTemplate {
    active_page: String,
}

#[derive(Template)]
#[template(path = "users/users.html")]
struct UsersListTemplate {
    active_page: String,
}

#[derive(Template)]
#[template(path = "users/groups.html")]
struct GroupsTemplate {
    active_page: String,
}

#[derive(Template)]
#[template(path = "users/settings.html")]
struct UsersSettingsTemplate {
    active_page: String,
}

#[derive(Template)]
#[template(path = "services/ssh.html")]
struct SshTemplate {
    active_page: String,
    ssh_enabled: bool,
    ssh_port: u16,
    permit_root_login: bool,
    password_auth: bool,
    pubkey_auth: bool,
}

#[derive(Template)]
#[template(path = "services/index.html")]
struct ServicesTemplate {
    active_page: String,
}

#[derive(Template)]
#[template(path = "services/rsync.html")]
struct RsyncTemplate {
    active_page: String,
    rsync_enabled: bool,
    #[allow(dead_code)]
    modules: Vec<RsyncModuleView>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct RsyncModuleView {
    name: String,
    path: String,
    read_only: bool,
}

#[derive(Template)]
#[template(path = "system/index.html")]
struct SystemTemplate {
    active_page: String,
    generations: Vec<GenerationInfo>,
}

#[derive(Template)]
#[template(path = "system/settings.html")]
struct SettingsTemplate {
    active_page: String,
    hostname: String,
}

#[derive(Template)]
#[template(path = "system/notifications.html")]
struct NotificationsTemplate {
    active_page: String,
    config: NotificationConfig,
}

#[derive(Template)]
#[template(path = "partials/build_output.html")]
struct BuildOutputTemplate {
    success: bool,
    title: String,
    output: String,
    error: String,
}

#[derive(Clone)]
struct FilesystemInfo {
    filesystem: String,
    mountpoint: String,
    size_human: String,
    used_human: String,
    available_human: String,
    use_percent: u8,
}

#[derive(Clone)]
#[allow(dead_code)]
struct DiskInfo {
    name: String,
    path: String,
    model: String,
    serial: String,
    label: String,
    size_human: String,
    device_type: String,
    mountpoint: String,
    fstype: String,
    rotational: bool,
    slot: String,         // Physical slot (e.g., "1", "Bay 1")
    slot_label: String,   // Optional description
    by_id: String,        // /dev/disk/by-id path for identification
    smart_status: String, // "ok", "warning", "failed", "unknown"
    children: Vec<DiskInfo>,
}

#[derive(Clone)]
struct PoolInfo {
    name: String,
    health: String,
    size_human: String,
    used_human: String,
    free_human: String,
    capacity: u8,
    fragmentation: u8,
    scrub_in_progress: bool,
    datasets: Vec<DatasetInfo>,
    snapshots: Vec<SnapshotInfo>,
}

#[derive(Clone)]
struct DatasetInfo {
    name: String,
    used_human: String,
    available_human: String,
    mountpoint: String,
}

#[derive(Clone)]
struct SnapshotInfo {
    name: String,
    used_human: String,
    creation: String,
    mountpoint: Option<String>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ArrayInfo {
    id: String,
    device: String,
    level: String,
    state: String,
    device_count: u32,
    size_human: String,
    rebuild_progress: String,
    devices: Vec<ArrayDeviceInfo>,
}

#[derive(Clone)]
struct ArrayDeviceInfo {
    path: String,
    state: String,
}

#[derive(Clone)]
#[allow(dead_code)]
struct SmartDiskInfo {
    name: String,
    path: String,
    model: String,
    serial: String,
    size_human: String,
    rotational: bool,
    is_virtual: bool,
    health: String,
    health_ok: bool,
    temperature: String,
    power_on_hours: String,
    power_cycles: String,
    monitoring_enabled: bool,
}

#[derive(Clone)]
#[allow(dead_code)]
struct BtrfsInfo {
    uuid: String,
    label: String,
    device_count: usize,
    devices: Vec<BtrfsDeviceInfo>,
    total_size: String,
    data_profile: String,
    metadata_profile: String,
    mountpoint: String,
}

#[derive(Clone)]
struct BtrfsDeviceInfo {
    devid: u32,
    path: String,
    size_human: String,
}

#[derive(Clone)]
struct GenerationInfo {
    id: u32,
    date: String,
    current: bool,
}

#[derive(Clone)]
struct SmbShareView {
    id: String,
    name: String,
    path: String,
    comment: String,
    guest_ok: bool,
    guest_only: bool,
    read_only: bool,
    browseable: bool,
    valid_users: String,
    invalid_users: String,
    write_list: String,
    read_list: String,
    force_user: String,
    force_group: String,
    create_mask: String,
    directory_mask: String,
    force_create_mode: String,
    force_directory_mode: String,
    inherit_acls: bool,
    inherit_permissions: bool,
    ea_support: bool,
    store_dos_attributes: bool,
    hide_dot_files: bool,
    hide_special_files: bool,
    follow_symlinks: bool,
    wide_links: bool,
    vfs_objects: String,
    time_machine: bool,
    hosts_allow: String,
    hosts_deny: String,
    recycle_bin: bool,
    recycle_max_size: u64,
    recycle_retention_days: u32,
    audit_enabled: bool,
    smb_encrypt: String,
    extra_options: String,
}

impl From<SmbShare> for SmbShareView {
    fn from(s: SmbShare) -> Self {
        Self {
            id: s.id.to_string(),
            name: s.name,
            path: s.path,
            comment: s.comment,
            guest_ok: s.guest_ok,
            guest_only: s.guest_only,
            read_only: s.read_only,
            browseable: s.browseable,
            valid_users: s.valid_users.join(" "),
            invalid_users: s.invalid_users.join(" "),
            write_list: s.write_list.join(" "),
            read_list: s.read_list.join(" "),
            force_user: s.force_user.unwrap_or_default(),
            force_group: s.force_group.unwrap_or_default(),
            create_mask: s.create_mask,
            directory_mask: s.directory_mask,
            force_create_mode: s.force_create_mode.unwrap_or_default(),
            force_directory_mode: s.force_directory_mode.unwrap_or_default(),
            inherit_acls: s.inherit_acls,
            inherit_permissions: s.inherit_permissions,
            ea_support: s.ea_support,
            store_dos_attributes: s.store_dos_attributes,
            hide_dot_files: s.hide_dot_files,
            hide_special_files: s.hide_special_files,
            follow_symlinks: s.follow_symlinks,
            wide_links: s.wide_links,
            vfs_objects: s.vfs_objects.join(" "),
            time_machine: s.time_machine,
            hosts_allow: s.hosts_allow.join(" "),
            hosts_deny: s.hosts_deny.join(" "),
            recycle_bin: s.recycle_bin,
            recycle_max_size: s.recycle_max_size,
            recycle_retention_days: s.recycle_retention_days,
            audit_enabled: s.audit_enabled,
            smb_encrypt: s.smb_encrypt,
            extra_options: s.extra_options,
        }
    }
}

#[derive(Clone)]
struct NfsExportView {
    id: String,
    path: String,
    clients: Vec<NfsClientView>,
}

#[derive(Clone)]
struct NfsClientView {
    host: String,
}

impl From<NfsExport> for NfsExportView {
    fn from(e: NfsExport) -> Self {
        Self {
            id: e.id.to_string(),
            path: e.path,
            clients: e
                .clients
                .into_iter()
                .map(|c| NfsClientView { host: c.host })
                .collect(),
        }
    }
}

struct HtmlTemplate<T>(T);

impl<T: Template> IntoResponse for HtmlTemplate<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => {
                tracing::error!("Template error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
            }
        }
    }
}

/// Extract token from cookie
fn get_token_from_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| {
            let cookie = cookie.trim();
            cookie.strip_prefix("token=").map(|s| s.to_string())
        })
}

/// Auth middleware - redirects to /login if not authenticated
async fn auth_middleware(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if let Some(token) = get_token_from_cookie(&headers)
        && state.auth.validate_token(&token).await.is_ok()
    {
        return next.run(request).await;
    }

    Redirect::to("/login").into_response()
}

/// Serve the embedded CSS stylesheet
async fn serve_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLESHEET,
    )
}

/// Serve Pico CSS
async fn serve_pico_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        PICO_CSS,
    )
}

/// Serve HTMX JS
async fn serve_htmx_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        HTMX_JS,
    )
}

pub fn build_web_router(state: Arc<WebState>) -> Router {
    let public_routes = Router::new()
        .route("/login", get(login_page))
        .route("/logout", get(logout_handler))
        .route("/static/style.css", get(serve_css))
        .route("/static/pico.min.css", get(serve_pico_css))
        .route("/static/htmx.min.js", get(serve_htmx_js));

    let protected_routes = Router::new()
        .route("/", get(dashboard))
        .route("/settings", get(settings_page))
        .route("/storage/disks", get(disks_page))
        .route("/storage/smart", get(smart_page))
        .route("/storage/zfs", get(zfs_page))
        .route("/storage/btrfs", get(btrfs_page))
        .route("/storage/raid", get(raid_page))
        .route("/services", get(services_page))
        .route("/services/smb", get(smb_page))
        .route("/services/nfs", get(nfs_page))
        .route("/services/ssh", get(ssh_page))
        .route("/services/rsync", get(rsync_page))
        .route("/users", get(users_page))
        .route("/users/settings", get(users_settings_page))
        .route("/users/groups", get(groups_page))
        .route("/system", get(system_page))
        .route("/system/notifications", get(notifications_page))
        .route("/api/web/metrics/ws", get(metrics_websocket))
        .route("/api/web/metrics/snapshot", get(metrics_snapshot))
        .route("/api/web/metrics/history", get(metrics_history))
        .route("/api/web/settings/hostname", post(update_hostname))
        .route("/api/web/settings/password", post(change_password))
        .route("/api/web/notifications/smtp", post(update_smtp_settings))
        .route(
            "/api/web/notifications/events",
            post(update_notification_events),
        )
        .route("/api/web/notifications/test", post(send_test_notification))
        .route("/api/web/storage/available-disks", get(available_disks))
        .route("/api/web/storage/format", post(format_disk))
        .route("/api/web/storage/wipe/{name}", post(wipe_disk))
        .route("/api/web/storage/scan", post(scan_disks))
        .route("/api/web/storage/mount", post(mount_device))
        .route("/api/web/storage/umount", post(umount_device))
        .route("/api/web/storage/disk-slot", post(set_disk_slot))
        .route("/api/web/storage/disk-slot/remove", post(remove_disk_slot))
        .route("/api/web/smart/{name}", get(get_smart_info))
        .route("/api/web/smart/{name}/config", get(get_smart_config_form))
        .route("/api/web/smart/{name}/config", post(save_smart_config))
        .route(
            "/api/web/smart/{name}/test/{test_type}",
            post(start_smart_test),
        )
        .route("/api/web/zfs/pools", post(create_zfs_pool))
        .route("/api/web/zfs/pools/{name}", delete(delete_zfs_pool))
        .route("/api/web/zfs/pools/{name}/export", post(export_zfs_pool))
        .route("/api/web/zfs/pools/{name}/scrub", post(scrub_zfs_pool))
        .route(
            "/api/web/zfs/pools/{name}/scrub/stop",
            post(stop_scrub_zfs_pool),
        )
        .route(
            "/api/web/zfs/pools/{name}/properties",
            get(get_zfs_pool_properties),
        )
        .route(
            "/api/web/zfs/pools/{name}/properties",
            post(set_zfs_pool_property),
        )
        .route("/api/web/zfs/importable", get(get_importable_pools))
        .route("/api/web/zfs/import/{name}", post(import_zfs_pool))
        .route("/api/web/zfs/datasets", post(create_zfs_dataset))
        .route(
            "/api/web/zfs/datasets/delete/{*name}",
            delete(delete_zfs_dataset),
        )
        .route("/api/web/zfs/snapshots", post(create_zfs_snapshot))
        .route(
            "/api/web/zfs/snapshots/rollback/{*name}",
            post(rollback_zfs_snapshot),
        )
        .route(
            "/api/web/zfs/snapshots/delete/{*name}",
            delete(delete_zfs_snapshot),
        )
        .route(
            "/api/web/zfs/snapshots/mount/{*name}",
            post(mount_zfs_snapshot),
        )
        .route(
            "/api/web/zfs/snapshots/unmount/{*name}",
            post(unmount_zfs_snapshot),
        )
        .route("/api/web/zfs/policies", get(list_snapshot_policies))
        .route("/api/web/zfs/policies", post(create_snapshot_policy))
        .route("/api/web/zfs/policies/{id}", put(update_snapshot_policy))
        .route("/api/web/zfs/policies/{id}", delete(delete_snapshot_policy))
        .route("/api/web/zfs/policies/{id}/edit", get(get_policy_edit_form))
        .route(
            "/api/web/zfs/policies/{id}/toggle",
            post(toggle_snapshot_policy),
        )
        .route("/api/web/zfs/settings", get(get_zfs_settings))
        .route("/api/web/zfs/settings", post(update_zfs_settings))
        .route("/api/web/btrfs/create", post(create_btrfs))
        .route("/api/web/btrfs/add-device", post(btrfs_add_device))
        .route("/api/web/mdadm/arrays", post(create_mdadm_array))
        .route("/api/web/mdadm/arrays/{name}", delete(delete_mdadm_array))
        .route(
            "/api/web/mdadm/arrays/{name}/add-device",
            post(mdadm_add_device),
        )
        .route("/api/web/mdadm/arrays/{name}/grow", post(mdadm_grow_array))
        .route("/api/web/zfs/pools/{name}/add-vdev", post(zfs_add_vdev))
        .route("/api/web/zfs/pools/{name}/add-spare", post(zfs_add_spare))
        .route("/api/web/zfs/pools/{name}/add-cache", post(zfs_add_cache))
        .route("/api/web/zfs/pools/{name}/attach", post(zfs_attach_device))
        .route(
            "/api/web/zfs/pools/{name}/replace",
            post(zfs_replace_device),
        )
        .route("/api/web/zfs/pools/{name}/clear", post(zfs_clear_errors))
        .route("/api/web/zfs/pools/{name}/status", get(zfs_pool_status_raw))
        .route("/api/web/zfs/pools/{name}/vdevs", get(zfs_pool_vdevs))
        .route("/api/web/zfs/pools/{name}/devices", get(zfs_pool_devices))
        .route(
            "/api/web/storage/available-disks-select",
            get(available_disks_select),
        )
        .route("/api/web/smb/shares", post(create_smb_share))
        .route("/api/web/smb/shares/{id}/edit", get(get_smb_edit_form))
        .route("/api/web/smb/shares/{id}", put(update_smb_share))
        .route("/api/web/smb/shares/{id}", delete(delete_smb_share))
        .route("/api/web/smb/shares/{id}/acl", get(get_share_acl))
        .route("/api/web/smb/shares/{id}/acl", post(add_share_acl))
        .route(
            "/api/web/smb/shares/{id}/acl/{acl_type}/{name}",
            delete(remove_share_acl),
        )
        .route(
            "/api/web/smb/shares/{id}/acl/all",
            delete(remove_all_share_acl),
        )
        .route(
            "/api/web/smb/shares/{id}/privileges",
            get(get_share_privileges),
        )
        .route(
            "/api/web/smb/shares/{id}/privileges",
            post(save_share_privileges),
        )
        .route(
            "/api/web/smb/shares/{id}/privileges/{priv_type}/{name}",
            delete(delete_share_privilege),
        )
        .route("/api/web/smb/toggle", post(toggle_smb))
        .route("/api/web/smb/global-settings", get(get_smb_global_settings))
        .route(
            "/api/web/smb/global-settings",
            post(update_smb_global_settings),
        )
        .route("/api/web/smb/users", get(list_samba_users))
        .route("/api/web/smb/users", post(create_samba_user))
        .route("/api/web/smb/users/{id}", delete(delete_samba_user))
        .route(
            "/api/web/smb/users/{id}/password",
            post(set_samba_user_password),
        )
        .route("/api/web/smb/users/{id}/toggle", post(toggle_samba_user))
        .route("/api/web/nfs/exports", post(create_nfs_export))
        .route("/api/web/nfs/exports/{id}", delete(delete_nfs_export))
        .route("/api/web/nfs/toggle", post(toggle_nfs))
        .route("/api/web/nfs/settings", get(get_nfs_settings))
        .route("/api/web/nfs/settings", post(update_nfs_settings))
        .route("/api/web/users/list", get(list_system_users))
        .route("/api/web/users", post(create_system_user))
        .route("/api/web/users/{id}", get(get_system_user))
        .route("/api/web/users/{id}", put(update_system_user))
        .route("/api/web/users/{id}", delete(delete_system_user))
        .route(
            "/api/web/users/{id}/password",
            post(set_system_user_password),
        )
        .route("/api/web/users/home-settings", get(get_home_settings))
        .route("/api/web/users/home-settings", post(update_home_settings))
        .route("/api/web/groups/list", get(list_system_groups))
        .route("/api/web/groups", post(create_system_group))
        .route("/api/web/groups/{id}", delete(delete_system_group))
        .route("/api/web/ssh/toggle", post(toggle_ssh))
        .route("/api/web/ssh/settings", post(update_ssh_settings))
        .route("/api/web/rsync/toggle", post(toggle_rsync))
        .route("/api/web/rsync/modules/list", get(list_rsync_modules))
        .route("/api/web/rsync/modules", post(create_rsync_module))
        .route("/api/web/rsync/modules/{name}", delete(delete_rsync_module))
        .route("/api/web/system/dry-build", post(dry_build))
        .route("/api/web/system/apply", post(apply_config))
        .route("/api/web/system/rollback", post(rollback))
        .route("/api/web/system/upgrade", post(upgrade_system))
        .route(
            "/api/web/system/switch/{generation}",
            post(switch_generation),
        )
        .route("/api/web/system/config/{file}", get(get_config_file))
        .route("/api/web/system/pending", get(get_pending_status))
        .route("/api/web/system/backups", get(list_backups))
        .route(
            "/api/web/system/backups/restore/{filename}",
            post(restore_backup),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    public_routes.merge(protected_routes).with_state(state)
}

async fn login_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let needs_setup = state.auth.needs_setup().await;
    HtmlTemplate(LoginTemplate { needs_setup })
}

async fn logout_handler() -> impl IntoResponse {
    (
        [(
            header::SET_COOKIE,
            "token=; path=/; max-age=0; SameSite=Strict",
        )],
        Redirect::to("/login"),
    )
}

async fn settings_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let settings = state.state_manager.get_settings().await;
    HtmlTemplate(SettingsTemplate {
        active_page: "settings".to_string(),
        hostname: settings.hostname,
    })
}

#[derive(Deserialize)]
struct HostnameForm {
    hostname: String,
}

async fn update_hostname(
    State(state): State<Arc<WebState>>,
    Form(form): Form<HostnameForm>,
) -> impl IntoResponse {
    let hostname = form.hostname.trim();
    if hostname.is_empty() || hostname.len() > 63 {
        return Html(
            r#"<div class="error">Invalid hostname. Must be 1-63 characters.</div>"#.to_string(),
        );
    }

    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Html(
            r#"<div class="error">Hostname can only contain letters, numbers, and hyphens.</div>"#
                .to_string(),
        );
    }

    if let Err(e) = state.state_manager.set_hostname(hostname.to_string()).await {
        return Html(format!(
            r#"<div class="error">Failed to update hostname: {}</div>"#,
            e
        ));
    }

    let _ = state.nix.generate_all().await;

    Html(
        r#"<div class="success">✅ Hostname updated. Apply changes to activate.</div>"#.to_string(),
    )
}

#[derive(Deserialize)]
struct ChangePasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

async fn change_password(
    State(state): State<Arc<WebState>>,
    Form(form): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    if form.new_password.len() < 8 {
        return Html(
            r#"<div class="error">New password must be at least 8 characters.</div>"#.to_string(),
        );
    }

    if form.new_password != form.confirm_password {
        return Html(r#"<div class="error">Passwords do not match.</div>"#.to_string());
    }

    match state
        .auth
        .change_password(&form.current_password, &form.new_password)
        .await
    {
        Ok(()) => {
            Html(r#"<div class="success">✅ Password changed successfully.</div>"#.to_string())
        }
        Err(_) => Html(r#"<div class="error">Invalid current password.</div>"#.to_string()),
    }
}

async fn notifications_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    HtmlTemplate(NotificationsTemplate {
        active_page: "notifications".to_string(),
        config: nas_state.notifications.clone(),
    })
}

#[derive(Deserialize)]
struct SmtpSettingsForm {
    #[serde(default)]
    enabled: Option<String>,
    server: String,
    port: u16,
    encryption: String,
    sender: String,
    #[serde(default)]
    auth_required: Option<String>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    recipient: String,
    #[serde(default)]
    recipient_secondary: Option<String>,
}

async fn update_smtp_settings(
    State(state): State<Arc<WebState>>,
    Form(form): Form<SmtpSettingsForm>,
) -> impl IntoResponse {
    if form.server.is_empty() {
        return Html(r#"<div class="error">SMTP server is required.</div>"#.to_string());
    }
    if form.sender.is_empty() {
        return Html(r#"<div class="error">Sender address is required.</div>"#.to_string());
    }
    if form.recipient.is_empty() {
        return Html(r#"<div class="error">Recipient email is required.</div>"#.to_string());
    }

    let result = state
        .state_manager
        .update(|s| {
            s.notifications.enabled = form.enabled.is_some();
            s.notifications.smtp = SmtpConfig {
                server: form.server.clone(),
                port: form.port,
                encryption: SmtpEncryption::from_str(&form.encryption),
                sender: form.sender.clone(),
                auth_required: form.auth_required.is_some(),
                username: form.username.clone(),
                password: form.password.clone(),
                recipient: form.recipient.clone(),
                recipient_secondary: form.recipient_secondary.clone().filter(|s| !s.is_empty()),
            };
        })
        .await;

    match result {
        Ok(_) => Html(r#"<div class="success">✅ SMTP settings saved.</div>"#.to_string()),
        Err(e) => Html(format!(r#"<div class="error">Failed to save: {}</div>"#, e)),
    }
}

#[derive(Deserialize)]
struct NotificationEventsForm {
    #[serde(default)]
    disk_space_warning: Option<String>,
    #[serde(default)]
    disk_space_critical: Option<String>,
    #[serde(default)]
    smart_errors: Option<String>,
    #[serde(default)]
    zfs_pool_errors: Option<String>,
    #[serde(default)]
    zfs_scrub_complete: Option<String>,
    #[serde(default)]
    raid_errors: Option<String>,
    #[serde(default)]
    service_failures: Option<String>,
    #[serde(default)]
    system_startup: Option<String>,
    #[serde(default)]
    system_shutdown: Option<String>,
    #[serde(default)]
    high_cpu_usage: Option<String>,
    #[serde(default)]
    high_memory_usage: Option<String>,
    #[serde(default)]
    high_temperature: Option<String>,
}

async fn update_notification_events(
    State(state): State<Arc<WebState>>,
    Form(form): Form<NotificationEventsForm>,
) -> impl IntoResponse {
    let result = state
        .state_manager
        .update(|s| {
            s.notifications.events = NotificationEvents {
                disk_space_warning: form.disk_space_warning.is_some(),
                disk_space_critical: form.disk_space_critical.is_some(),
                smart_errors: form.smart_errors.is_some(),
                zfs_pool_errors: form.zfs_pool_errors.is_some(),
                zfs_scrub_complete: form.zfs_scrub_complete.is_some(),
                raid_errors: form.raid_errors.is_some(),
                service_failures: form.service_failures.is_some(),
                system_startup: form.system_startup.is_some(),
                system_shutdown: form.system_shutdown.is_some(),
                high_cpu_usage: form.high_cpu_usage.is_some(),
                high_memory_usage: form.high_memory_usage.is_some(),
                high_temperature: form.high_temperature.is_some(),
            };
        })
        .await;

    match result {
        Ok(_) => Html(r#"<div class="success">✅ Event settings saved.</div>"#.to_string()),
        Err(e) => Html(format!(r#"<div class="error">Failed to save: {}</div>"#, e)),
    }
}

async fn send_test_notification(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    let settings = state.state_manager.get_settings().await;

    if !nas_state.notifications.enabled {
        return Html(
            r#"<div class="error">Notifications are disabled. Enable them first.</div>"#
                .to_string(),
        );
    }

    let service = NotificationService::new(nas_state.notifications.clone(), settings.hostname);

    match service.send_test().await {
        Ok(_) => {
            Html(r#"<div class="success">✅ Test email sent! Check your inbox.</div>"#.to_string())
        }
        Err(e) => Html(format!(r#"<div class="error">Failed to send: {}</div>"#, e)),
    }
}

/// WebSocket endpoint for real-time metrics
async fn metrics_websocket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_metrics_socket(socket, state))
}

async fn handle_metrics_socket(socket: WebSocket, _state: Arc<WebState>) {
    let (mut sender, mut receiver) = socket.split();

    let send_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

        loop {
            interval.tick().await;

            match MetricsStore::get_snapshot().await {
                Ok(snapshot) => {
                    if let Ok(json) = serde_json::to_string(&snapshot)
                        && sender.send(Message::Text(json.into())).await.is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to get metrics snapshot: {}", e);
                }
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }
}

/// Get current metrics snapshot (JSON)
async fn metrics_snapshot() -> impl IntoResponse {
    match MetricsStore::get_snapshot().await {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// Get metrics history (JSON)
#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_history_minutes")]
    minutes: usize,
}

fn default_history_minutes() -> usize {
    60
}

async fn metrics_history(
    State(state): State<Arc<WebState>>,
    axum::extract::Query(query): axum::extract::Query<HistoryQuery>,
) -> impl IntoResponse {
    let history = state.metrics.get_history(query.minutes).await;
    Json(history)
}

async fn dashboard(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let system_info = gather_system_info().await;
    let memory = gather_memory_info().await;
    let load_avg = gather_load_avg().await;
    let services = gather_services_status().await;
    let network_interfaces = gather_network_interfaces().await;

    let settings = state.state_manager.get_settings().await;
    let enabled_disks: Vec<String> = settings
        .smart_configs
        .iter()
        .filter(|c| c.enabled)
        .map(|c| c.disk_name.clone())
        .collect();

    // Read from cache only - background task handles refresh
    let disk_temps = gather_disk_temps(&state.smart_cache, &enabled_disks).await;
    let smart_status = gather_smart_status(&state.smart_cache, &enabled_disks).await;
    let zfs_arc = gather_zfs_arc().await;

    let smb_config = state.state_manager.get_smb().await;
    let nfs_config = state.state_manager.get_nfs().await;
    let disks = filesystem::list_disks().await.unwrap_or_default();
    let usage = filesystem::get_usage().await.unwrap_or_default();
    let zfs_pools = if zfs::is_available().await {
        zfs::list_pools().await.unwrap_or_default()
    } else {
        vec![]
    };

    let filesystems: Vec<FilesystemInfo> = usage
        .into_iter()
        .filter(|u| !u.filesystem.starts_with("tmpfs") && !u.filesystem.starts_with("devtmpfs"))
        .map(|u| FilesystemInfo {
            filesystem: u.filesystem,
            mountpoint: u.mountpoint,
            size_human: format_bytes(u.size),
            used_human: format_bytes(u.used),
            available_human: format_bytes(u.available),
            use_percent: u.use_percent,
        })
        .collect();

    HtmlTemplate(DashboardTemplate {
        active_page: "dashboard".to_string(),
        system_info,
        memory,
        load_avg,
        services,
        network_interfaces,
        disk_temps,
        smart_status,
        zfs_arc,
        disk_count: disks.len(),
        smb_share_count: smb_config.shares.len(),
        nfs_export_count: nfs_config.exports.len(),
        zfs_pool_count: zfs_pools.len(),
        filesystems,
    })
}

async fn gather_system_info() -> SystemInfoView {
    use tokio::process::Command;

    let hostname = tokio::fs::read_to_string("/etc/hostname")
        .await
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let kernel = Command::new("uname")
        .arg("-r")
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let arch = Command::new("uname")
        .arg("-m")
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let uptime = tokio::fs::read_to_string("/proc/uptime")
        .await
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|s| s.to_string()))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|secs| {
            let days = (secs / 86400.0) as u64;
            let hours = ((secs % 86400.0) / 3600.0) as u64;
            let mins = ((secs % 3600.0) / 60.0) as u64;
            if days > 0 {
                format!("{} days, {}h {}m", days, hours, mins)
            } else if hours > 0 {
                format!("{}h {}m", hours, mins)
            } else {
                format!("{}m", mins)
            }
        })
        .unwrap_or_else(|| "-".to_string());

    let datetime = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let cpuinfo = tokio::fs::read_to_string("/proc/cpuinfo")
        .await
        .unwrap_or_default();

    let cpu_model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Unknown CPU".to_string());

    let cpu_cores = cpuinfo
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();

    // Calculate CPU usage from /proc/stat (instant snapshot)
    let cpu_usage_percent = calculate_cpu_usage().await;

    SystemInfoView {
        hostname,
        kernel,
        arch,
        uptime,
        datetime,
        cpu_model,
        cpu_cores,
        cpu_usage_percent,
    }
}

async fn calculate_cpu_usage() -> u8 {
    // Read /proc/stat twice with a small delay to calculate CPU usage
    let read_cpu_times = || async {
        let stat = tokio::fs::read_to_string("/proc/stat").await.ok()?;
        let cpu_line = stat.lines().next()?;
        let parts: Vec<u64> = cpu_line
            .split_whitespace()
            .skip(1) // skip "cpu"
            .filter_map(|s| s.parse().ok())
            .collect();

        if parts.len() >= 4 {
            let user = parts[0];
            let nice = parts[1];
            let system = parts[2];
            let idle = parts[3];
            let iowait = parts.get(4).copied().unwrap_or(0);
            let irq = parts.get(5).copied().unwrap_or(0);
            let softirq = parts.get(6).copied().unwrap_or(0);
            let steal = parts.get(7).copied().unwrap_or(0);

            let total = user + nice + system + idle + iowait + irq + softirq + steal;
            let idle_total = idle + iowait;
            Some((total, idle_total))
        } else {
            None
        }
    };

    let Some((total1, idle1)) = read_cpu_times().await else {
        return 0;
    };

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let Some((total2, idle2)) = read_cpu_times().await else {
        return 0;
    };

    let total_diff = total2.saturating_sub(total1);
    let idle_diff = idle2.saturating_sub(idle1);

    if total_diff == 0 {
        return 0;
    }

    let usage = ((total_diff - idle_diff) as f64 / total_diff as f64) * 100.0;
    usage.round() as u8
}

async fn gather_memory_info() -> MemoryInfoView {
    let meminfo = tokio::fs::read_to_string("/proc/meminfo")
        .await
        .unwrap_or_default();

    let parse_kb = |name: &str| -> u64 {
        meminfo
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
            * 1024 // Convert KB to bytes
    };

    let total = parse_kb("MemTotal:");
    let available = parse_kb("MemAvailable:");
    let used = total.saturating_sub(available);
    let used_percent = if total > 0 {
        ((used as f64 / total as f64) * 100.0) as u8
    } else {
        0
    };

    let swap_total = parse_kb("SwapTotal:");
    let swap_free = parse_kb("SwapFree:");
    let swap_used = swap_total.saturating_sub(swap_free);
    let swap_percent = if swap_total > 0 {
        ((swap_used as f64 / swap_total as f64) * 100.0) as u8
    } else {
        0
    };

    MemoryInfoView {
        total: format_bytes(total),
        used: format_bytes(used),
        available: format_bytes(available),
        used_percent,
        swap_total: format_bytes(swap_total),
        swap_used: format_bytes(swap_used),
        swap_percent,
    }
}

async fn gather_load_avg() -> LoadAvgView {
    let loadavg = tokio::fs::read_to_string("/proc/loadavg")
        .await
        .unwrap_or_default();

    let parts: Vec<&str> = loadavg.split_whitespace().collect();
    let load1 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let load5 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let load15 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);

    LoadAvgView {
        load1,
        load5,
        load15,
        load1_str: format!("{:.2}", load1),
        load5_str: format!("{:.2}", load5),
        load15_str: format!("{:.2}", load15),
    }
}

async fn gather_services_status() -> Vec<ServiceStatusView> {
    use tokio::process::Command;

    let services = ["samba-smbd", "nfs-server", "sshd", "rsyncd"];
    let mut result = Vec::new();

    for svc in services {
        let output = Command::new("systemctl")
            .args(["is-active", svc])
            .output()
            .await;

        let active = output
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);

        let name = match svc {
            "samba-smbd" => "SMB/CIFS",
            "nfs-server" => "NFS",
            "sshd" => "SSH",
            "rsyncd" => "Rsync",
            _ => svc,
        };

        result.push(ServiceStatusView {
            name: name.to_string(),
            active,
        });
    }

    result
}

async fn gather_network_interfaces() -> Vec<NetworkInterfaceView> {
    use tokio::process::Command;

    let output = Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .await;

    let mut interfaces = Vec::new();

    if let Ok(output) = output
        && let Ok(json) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout)
    {
        for iface in json {
            let name = iface["ifname"].as_str().unwrap_or("").to_string();

            // Skip loopback and virtual interfaces
            if name == "lo"
                || name.starts_with("veth")
                || name.starts_with("docker")
                || name.starts_with("br-")
            {
                continue;
            }

            let is_up = iface["operstate"].as_str() == Some("UP");

            let ipv4 = iface["addr_info"]
                .as_array()
                .and_then(|addrs| addrs.iter().find(|a| a["family"].as_str() == Some("inet")))
                .map(|a| {
                    format!(
                        "{}/{}",
                        a["local"].as_str().unwrap_or("-"),
                        a["prefixlen"].as_u64().unwrap_or(0)
                    )
                })
                .unwrap_or_else(|| "-".to_string());

            let speed_path = format!("/sys/class/net/{}/speed", name);
            let speed = tokio::fs::read_to_string(&speed_path)
                .await
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
                .filter(|&s| s > 0)
                .map(|s| format!("{} Mbps", s))
                .unwrap_or_else(|| "-".to_string());

            interfaces.push(NetworkInterfaceView {
                name,
                ipv4,
                speed,
                is_up,
            });
        }
    }

    interfaces
}

async fn gather_disk_temps(
    cache: &crate::services::smart_cache::SmartCache,
    enabled_disks: &[String],
) -> Vec<DiskTempView> {
    // Early return if no disks have monitoring enabled
    if enabled_disks.is_empty() {
        return Vec::new();
    }

    let temps_from_cache = cache.get_temperatures().await;

    temps_from_cache
        .into_iter()
        .filter(|(name, _)| enabled_disks.contains(name))
        .map(|(name, temp)| DiskTempView { name, temp })
        .collect()
}

async fn gather_smart_status(
    cache: &crate::services::smart_cache::SmartCache,
    enabled_disks: &[String],
) -> Vec<SmartStatusView> {
    // Early return if no disks have monitoring enabled
    if enabled_disks.is_empty() {
        return Vec::new();
    }

    let statuses = cache.get_statuses().await;

    statuses
        .into_iter()
        .filter(|(name, _)| enabled_disks.contains(name))
        .map(|(name, status)| SmartStatusView {
            name,
            status: status.as_str().to_string(),
        })
        .collect()
}

async fn gather_zfs_arc() -> ZfsArcView {
    if !zfs::is_available().await {
        return ZfsArcView {
            hits: "0".to_string(),
            misses: "0".to_string(),
            total: 0,
            hit_percent: 0,
            size: "0 B".to_string(),
        };
    }

    let arcstats = tokio::fs::read_to_string("/proc/spl/kstat/zfs/arcstats")
        .await
        .unwrap_or_default();

    let parse_stat = |name: &str| -> u64 {
        arcstats
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };

    let hits = parse_stat("hits");
    let misses = parse_stat("misses");
    let total = hits + misses;
    let hit_percent = if total > 0 {
        ((hits as f64 / total as f64) * 100.0) as u8
    } else {
        0
    };
    let size = parse_stat("size");

    ZfsArcView {
        hits: format_number(hits),
        misses: format_number(misses),
        total,
        hit_percent,
        size: format_bytes(size),
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}G", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

async fn disks_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let block_devices = filesystem::list_block_devices().await.unwrap_or_default();
    let usage = filesystem::get_usage().await.unwrap_or_default();
    let by_id_map = filesystem::get_disk_by_id_map().await.unwrap_or_default();

    let disk_slots = state.state_manager.get().await.settings.disk_slots;

    let smart_statuses: std::collections::HashMap<String, String> = state
        .smart_cache
        .get_statuses()
        .await
        .into_iter()
        .map(|(name, status)| (name, status.as_str().to_string()))
        .collect();

    let disks: Vec<DiskInfo> = block_devices
        .into_iter()
        .filter(|d| d.device_type == "disk")
        .map(|d| {
            let by_id = by_id_map
                .get(&d.name)
                .cloned()
                .unwrap_or_else(|| d.path.clone());

            let (slot, slot_label) = disk_slots
                .iter()
                .find(|s| s.disk_id == by_id || s.disk_id == d.path || s.disk_id == d.name)
                .map(|s| (s.slot.clone(), s.label.clone()))
                .unwrap_or_default();

            let smart_status = smart_statuses
                .get(&d.name)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());

            DiskInfo {
                name: d.name.clone(),
                path: d.path.clone(),
                model: opt_to_string(&d.model),
                serial: opt_to_string(&d.serial),
                label: opt_to_string(&d.label),
                size_human: format_bytes(d.size),
                device_type: d.device_type.clone(),
                mountpoint: opt_to_string(&d.mountpoint),
                fstype: opt_to_string(&d.fstype),
                rotational: d.rotational,
                slot,
                slot_label,
                by_id: by_id.clone(),
                smart_status,
                children: d
                    .children
                    .into_iter()
                    .map(|c| DiskInfo {
                        name: c.name.clone(),
                        path: c.path.clone(),
                        model: String::new(),
                        serial: String::new(),
                        label: opt_to_string(&c.label),
                        size_human: format_bytes(c.size),
                        device_type: c.device_type.clone(),
                        mountpoint: opt_to_string(&c.mountpoint),
                        fstype: opt_to_string(&c.fstype),
                        rotational: false,
                        slot: String::new(),
                        slot_label: String::new(),
                        by_id: String::new(),
                        smart_status: String::new(),
                        children: vec![],
                    })
                    .collect(),
            }
        })
        .collect();

    let filesystems: Vec<FilesystemInfo> = usage
        .into_iter()
        .map(|u| FilesystemInfo {
            filesystem: u.filesystem,
            mountpoint: u.mountpoint,
            size_human: format_bytes(u.size),
            used_human: format_bytes(u.used),
            available_human: format_bytes(u.available),
            use_percent: u.use_percent,
        })
        .collect();

    HtmlTemplate(DisksTemplate {
        active_page: "disks".to_string(),
        disks,
        filesystems,
    })
}

#[derive(Template)]
#[template(path = "partials/disk_selector.html")]
struct DiskSelectorTemplate {
    disks: Vec<AvailableDisk>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct AvailableDisk {
    path: String,
    by_id: String,
    name: String,
    size_human: String,
    model: String,
}

async fn available_disks(State(_state): State<Arc<WebState>>) -> impl IntoResponse {
    let block_devices = filesystem::list_block_devices().await.unwrap_or_default();
    let by_id_map = filesystem::get_disk_by_id_map().await.unwrap_or_default();

    let zfs_devices = zfs::get_all_pool_devices().await;

    // Filter to only show unused disks (whole disks with no mounted partitions and not in ZFS)
    let disks: Vec<AvailableDisk> = block_devices
        .into_iter()
        .filter(|d| {
            if d.device_type != "disk" {
                return false;
            }
            if d.mountpoint.is_some() {
                return false;
            }
            if !d.children.iter().all(|c| c.mountpoint.is_none()) {
                return false;
            }
            let by_id = by_id_map.get(&d.name).cloned().unwrap_or_default();
            let is_in_zfs = zfs_devices.iter().any(|zd| {
                zd == &d.name
                    || zd == &d.path
                    || zd == &by_id
                    || by_id.ends_with(zd)
                    || zd.ends_with(&d.name)
            });
            !is_in_zfs
        })
        .map(|d| {
            let by_id = by_id_map
                .get(&d.name)
                .cloned()
                .unwrap_or_else(|| d.path.clone());
            AvailableDisk {
                path: d.path.clone(),
                by_id,
                name: d.name.clone(),
                size_human: format_bytes(d.size),
                model: opt_to_string(&d.model),
            }
        })
        .collect();

    HtmlTemplate(DiskSelectorTemplate { disks })
}

/// Returns available disks as <select> options
async fn available_disks_select(State(_state): State<Arc<WebState>>) -> impl IntoResponse {
    let block_devices = filesystem::list_block_devices().await.unwrap_or_default();
    let by_id_map = filesystem::get_disk_by_id_map().await.unwrap_or_default();

    let zfs_devices = zfs::get_all_pool_devices().await;

    let disks: Vec<AvailableDisk> = block_devices
        .into_iter()
        .filter(|d| {
            if d.device_type != "disk" {
                return false;
            }
            if d.mountpoint.is_some() {
                return false;
            }
            if !d.children.iter().all(|c| c.mountpoint.is_none()) {
                return false;
            }
            let by_id = by_id_map.get(&d.name).cloned().unwrap_or_default();
            let is_in_zfs = zfs_devices.iter().any(|zd| {
                zd == &d.name
                    || zd == &d.path
                    || zd == &by_id
                    || by_id.ends_with(zd)
                    || zd.ends_with(&d.name)
            });
            !is_in_zfs
        })
        .map(|d| {
            let by_id = by_id_map
                .get(&d.name)
                .cloned()
                .unwrap_or_else(|| d.path.clone());
            AvailableDisk {
                path: d.path.clone(),
                by_id,
                name: d.name.clone(),
                size_human: format_bytes(d.size),
                model: opt_to_string(&d.model),
            }
        })
        .collect();

    let mut html = String::from("<option value=\"\">-- Select a disk --</option>");
    for disk in disks {
        html.push_str(&format!(
            "<option value=\"{}\">{} - {} ({})</option>",
            disk.by_id, disk.name, disk.model, disk.size_human
        ));
    }
    Html(html)
}

/// Returns vdevs and devices of a ZFS pool as <select> options for attach
async fn zfs_pool_vdevs(Path(name): Path<String>) -> impl IntoResponse {
    let raw_status = match zfs::pool_status_raw(&name).await {
        Ok(s) => s,
        Err(e) => return Html(format!("<option value=\"\">Error: {}</option>", e)),
    };

    let mut html = String::from("<option value=\"\">-- Select target --</option>");

    let mut has_raidz = false;
    let mut devices = Vec::new();
    let mut in_config = false;

    for line in raw_status.lines() {
        if line.contains("NAME") && line.contains("STATE") {
            in_config = true;
            continue;
        }

        if line.starts_with("errors:") {
            break;
        }

        if !in_config {
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("raidz") {
            if !has_raidz {
                html.push_str("<optgroup label=\"RAIDZ Vdevs (expansion)\">");
                has_raidz = true;
            }
            let vdev_name = trimmed.split_whitespace().next().unwrap_or("");
            html.push_str(&format!(
                "<option value=\"{}\">{}</option>",
                vdev_name, vdev_name
            ));
        } else if !trimmed.starts_with("mirror")
            && !trimmed.starts_with("spare")
            && !trimmed.starts_with("cache")
            && !trimmed.starts_with("log")
            && !trimmed.starts_with(&name)
        {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if !parts.is_empty() {
                let device = parts[0];
                // Skip if it looks like a header or state
                if device != "NAME" && device != "STATE" {
                    devices.push(device.to_string());
                }
            }
        }
    }

    if has_raidz {
        html.push_str("</optgroup>");
    }

    if !devices.is_empty() {
        html.push_str("<optgroup label=\"Devices (mirror/convert to mirror)\">");
        for device in devices {
            let short_name = device.split('/').next_back().unwrap_or(&device);
            html.push_str(&format!(
                "<option value=\"{}\">{}</option>",
                device, short_name
            ));
        }
        html.push_str("</optgroup>");
    }

    Html(html)
}

/// Returns devices of a ZFS pool as <select> options
async fn zfs_pool_devices(Path(name): Path<String>) -> impl IntoResponse {
    let raw_status = match zfs::pool_status_raw(&name).await {
        Ok(s) => s,
        Err(e) => return Html(format!("<option value=\"\">Error: {}</option>", e)),
    };

    let mut html = String::from("<option value=\"\">-- Select a device --</option>");
    let mut in_config = false;

    for line in raw_status.lines() {
        if line.contains("NAME") && line.contains("STATE") {
            in_config = true;
            continue;
        }

        if line.starts_with("errors:") {
            break;
        }

        if !in_config {
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("raidz")
            || trimmed.starts_with("mirror")
            || trimmed.starts_with("spare")
            || trimmed.starts_with("cache")
            || trimmed.starts_with("log")
            || trimmed.starts_with(&name)
        {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            let device = parts[0];
            let state = parts[1];
            if device != "NAME" {
                let short_name = device.split('/').next_back().unwrap_or(device);
                html.push_str(&format!(
                    "<option value=\"{}\">{} ({})</option>",
                    device, short_name, state
                ));
            }
        }
    }

    Html(html)
}

/// Get raw pool status for display
async fn zfs_pool_status_raw(Path(name): Path<String>) -> impl IntoResponse {
    match zfs::pool_status_raw(&name).await {
        Ok(status) => Html(format!("<pre><code>{}</code></pre>", status)),
        Err(e) => Html(format!("<p class=\"error\">Error: {}</p>", e)),
    }
}

/// Clear pool errors
async fn zfs_clear_errors(Path(name): Path<String>) -> impl IntoResponse {
    match zfs::clear_errors(&name, None).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Errors Cleared".to_string(),
            output: format!("Cleared errors on pool {}", name),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Clear Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn smart_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let smart_available = smart::is_available().await;
    let settings = state.state_manager.get_settings().await;
    let smart_configs = settings.smart_configs.clone();

    let disks = if smart_available {
        let block_devices = filesystem::list_block_devices().await.unwrap_or_default();

        let (virtual_disks, physical_disks): (Vec<_>, Vec<_>) = block_devices
            .iter()
            .filter(|d| d.device_type == "disk")
            .partition(|d| {
                d.name.starts_with("vd")
                    || d.name.starts_with("xvd")
                    || d.name.starts_with("loop")
                    || d.name.starts_with("ram")
                    || d.name.starts_with("sr")
                    || d.name.starts_with("fd")
                    || d.name.starts_with("dm-")
                    || d.name.starts_with("md")
                    || d.name.starts_with("zram")
            });

        let mut smart_disks = Vec::new();

        for d in virtual_disks {
            smart_disks.push(SmartDiskInfo {
                name: d.name.clone(),
                path: d.path.clone(),
                model: opt_to_string(&d.model),
                serial: opt_to_string(&d.serial),
                size_human: format_bytes(d.size),
                rotational: d.rotational,
                is_virtual: true,
                health: "N/A".to_string(),
                health_ok: true,
                temperature: "—".to_string(),
                power_on_hours: "—".to_string(),
                power_cycles: "—".to_string(),
                monitoring_enabled: false,
            });
        }

        // Background monitoring service handles the refresh
        for d in physical_disks {
            let monitoring_enabled = smart_configs
                .iter()
                .find(|c| c.disk_name == d.name)
                .map(|c| c.enabled)
                .unwrap_or(false);

            let cached_info = state.smart_cache.get(&d.name).await;

            smart_disks.push(SmartDiskInfo {
                name: d.name.clone(),
                path: d.path.clone(),
                model: opt_to_string(&d.model),
                serial: opt_to_string(&d.serial),
                size_human: format_bytes(d.size),
                rotational: d.rotational,
                is_virtual: false,
                health: cached_info
                    .as_ref()
                    .map(|c| {
                        if c.info.health_passed {
                            "PASSED".to_string()
                        } else {
                            "FAILED".to_string()
                        }
                    })
                    .unwrap_or_else(|| "—".to_string()),
                health_ok: cached_info
                    .as_ref()
                    .map(|c| c.info.health_passed)
                    .unwrap_or(true),
                temperature: cached_info
                    .as_ref()
                    .and_then(|c| c.info.temperature)
                    .map(|t| format!("{}°C", t))
                    .unwrap_or_else(|| "—".to_string()),
                power_on_hours: cached_info
                    .as_ref()
                    .and_then(|c| c.info.power_on_hours)
                    .map(|h| format!("{} hrs", h))
                    .unwrap_or_else(|| "—".to_string()),
                power_cycles: cached_info
                    .as_ref()
                    .and_then(|c| c.info.power_cycle_count)
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "—".to_string()),
                monitoring_enabled,
            });
        }
        smart_disks
    } else {
        vec![]
    };

    HtmlTemplate(SmartTemplate {
        active_page: "smart".to_string(),
        smart_available,
        disks,
    })
}

/// Form data for SMART config
#[derive(Debug, Deserialize)]
struct SmartConfigForm {
    enabled: Option<String>,
    check_interval: u32,
    power_mode: String,
    #[serde(default)]
    temp_difference: String, // Can be empty string
    temp_max: i32,
}

async fn save_smart_config(
    State(state): State<Arc<WebState>>,
    Path(name): Path<String>,
    Form(form): Form<SmartConfigForm>,
) -> impl IntoResponse {
    let power_mode = match form.power_mode.as_str() {
        "never" => SmartPowerMode::Never,
        "sleep" => SmartPowerMode::Sleep,
        "idle" => SmartPowerMode::Idle,
        _ => SmartPowerMode::Standby,
    };

    // Parse temp_difference - empty string means None
    let temp_difference: Option<i32> = if form.temp_difference.is_empty() {
        None
    } else {
        form.temp_difference.parse().ok()
    };

    let new_interval = form.check_interval;

    let result = state
        .state_manager
        .update(|s| {
            // Sync check_interval across ALL disks (smartd has global interval)
            for cfg in &mut s.settings.smart_configs {
                cfg.check_interval = new_interval;
            }

            if let Some(cfg) = s
                .settings
                .smart_configs
                .iter_mut()
                .find(|c| c.disk_name == name)
            {
                cfg.enabled = form.enabled.is_some();
                cfg.check_interval = new_interval;
                cfg.power_mode = power_mode.clone();
                cfg.temp_difference = temp_difference;
                cfg.temp_max = form.temp_max;
            } else {
                s.settings.smart_configs.push(SmartDiskConfig {
                    disk_name: name.clone(),
                    enabled: form.enabled.is_some(),
                    check_interval: new_interval,
                    power_mode: power_mode.clone(),
                    temp_difference,
                    temp_max: form.temp_max,
                    last_temp: None,
                });
            }

            s.pending_changes = true;
        })
        .await;

    match result {
        Ok(_) => {
            let _ = state.nix.generate_all().await;
            Html(r#"<div class="alert alert-success">✅ Configuration saved. Apply changes to activate.</div>
                <script>htmx.ajax('GET', '/api/web/system/pending', {target: '#pending-banner', swap: 'outerHTML'});</script>"#.to_string())
        }
        Err(e) => Html(format!(
            "<div class=\"alert alert-error\">❌ Error: {}</div>",
            e
        )),
    }
}

async fn get_smart_config_form(
    State(state): State<Arc<WebState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let settings = state.state_manager.get_settings().await;

    let global_interval = settings
        .smart_configs
        .first()
        .map(|c| c.check_interval)
        .unwrap_or(1800);

    let config = settings
        .smart_configs
        .iter()
        .find(|c| c.disk_name == name)
        .cloned()
        .unwrap_or_else(|| SmartDiskConfig {
            disk_name: name.clone(),
            check_interval: global_interval,
            ..Default::default()
        });

    let checked = if config.enabled { "checked" } else { "" };
    let status = if config.enabled {
        "enabled"
    } else {
        "disabled"
    };
    let sel_never = if config.power_mode == SmartPowerMode::Never {
        "selected"
    } else {
        ""
    };
    let sel_sleep = if config.power_mode == SmartPowerMode::Sleep {
        "selected"
    } else {
        ""
    };
    let sel_standby = if config.power_mode == SmartPowerMode::Standby {
        "selected"
    } else {
        ""
    };
    let sel_idle = if config.power_mode == SmartPowerMode::Idle {
        "selected"
    } else {
        ""
    };
    let sel_diff_none = if config.temp_difference.is_none() {
        "selected"
    } else {
        ""
    };
    let sel_diff_5 = if config.temp_difference == Some(5) {
        "selected"
    } else {
        ""
    };
    let sel_diff_10 = if config.temp_difference == Some(10) {
        "selected"
    } else {
        ""
    };
    let sel_diff_15 = if config.temp_difference == Some(15) {
        "selected"
    } else {
        ""
    };
    let sel_diff_20 = if config.temp_difference == Some(20) {
        "selected"
    } else {
        ""
    };
    let sel_max_45 = if config.temp_max == 45 {
        "selected"
    } else {
        ""
    };
    let sel_max_50 = if config.temp_max == 50 {
        "selected"
    } else {
        ""
    };
    let sel_max_55 = if config.temp_max == 55 {
        "selected"
    } else {
        ""
    };
    let sel_max_60 = if config.temp_max == 60 {
        "selected"
    } else {
        ""
    };
    let sel_max_65 = if config.temp_max == 65 {
        "selected"
    } else {
        ""
    };
    let sel_max_70 = if config.temp_max == 70 {
        "selected"
    } else {
        ""
    };

    Html(format!(
        "<form hx-post=\"/api/web/smart/{name}/config\" hx-target=\"#config-result-{name}\" hx-swap=\"innerHTML\">
            <div class=\"smart-form-group\">
                <label class=\"toggle-switch\">
                    <input type=\"checkbox\" name=\"enabled\" value=\"true\" {checked}>
                    <span class=\"toggle-slider\"></span>
                </label>
                <span class=\"toggle-label\">Monitoring {status}</span>
            </div>

            <div class=\"smart-form-group\">
                <label>Check Interval (seconds)</label>
                <input type=\"number\" name=\"check_interval\" value=\"{interval}\" min=\"60\" max=\"86400\">
                <small>Global setting - applies to all disks (60-86400s)</small>
            </div>

            <div class=\"smart-form-group\">
                <label>Power Mode</label>
                <select name=\"power_mode\">
                    <option value=\"never\" {sel_never}>Never - check regardless of power state</option>
                    <option value=\"sleep\" {sel_sleep}>Sleep - check if not in sleep mode</option>
                    <option value=\"standby\" {sel_standby}>Standby - check if not in standby (recommended)</option>
                    <option value=\"idle\" {sel_idle}>Idle - check if not idle</option>
                </select>
                <small>Avoid waking disks in power-saving mode</small>
            </div>

            <div class=\"smart-form-group\">
                <label>Temperature Difference (°C)</label>
                <select name=\"temp_difference\">
                    <option value=\"\" {sel_diff_none}>Disabled</option>
                    <option value=\"5\" {sel_diff_5}>5°C</option>
                    <option value=\"10\" {sel_diff_10}>10°C</option>
                    <option value=\"15\" {sel_diff_15}>15°C</option>
                    <option value=\"20\" {sel_diff_20}>20°C</option>
                </select>
                <small>Notify if temperature changes by N degrees</small>
            </div>

            <div class=\"smart-form-group\">
                <label>Maximum Temperature (°C)</label>
                <select name=\"temp_max\">
                    <option value=\"45\" {sel_max_45}>45°C</option>
                    <option value=\"50\" {sel_max_50}>50°C</option>
                    <option value=\"55\" {sel_max_55}>55°C</option>
                    <option value=\"60\" {sel_max_60}>60°C (default)</option>
                    <option value=\"65\" {sel_max_65}>65°C</option>
                    <option value=\"70\" {sel_max_70}>70°C</option>
                </select>
                <small>Notify if temperature exceeds this threshold</small>
            </div>

            <div id=\"config-result-{name}\"></div>
            <button type=\"submit\" class=\"small\">💾 Save</button>
        </form>",
        name = name,
        checked = checked,
        status = status,
        interval = config.check_interval,
        sel_never = sel_never,
        sel_sleep = sel_sleep,
        sel_standby = sel_standby,
        sel_idle = sel_idle,
        sel_diff_none = sel_diff_none,
        sel_diff_5 = sel_diff_5,
        sel_diff_10 = sel_diff_10,
        sel_diff_15 = sel_diff_15,
        sel_diff_20 = sel_diff_20,
        sel_max_45 = sel_max_45,
        sel_max_50 = sel_max_50,
        sel_max_55 = sel_max_55,
        sel_max_60 = sel_max_60,
        sel_max_65 = sel_max_65,
        sel_max_70 = sel_max_70,
    ))
}

async fn get_smart_info(
    State(state): State<Arc<WebState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Read from cache instead of calling smartctl directly
    match state.smart_cache.get(&name).await {
        Some(cached) => {
            let mut html = String::from(
                r#"<table class="smart-table">
                <thead><tr>
                    <th>ID</th>
                    <th>Attribute</th>
                    <th style="text-align:right">Val</th>
                    <th style="text-align:right">Wst</th>
                    <th style="text-align:right">Thr</th>
                    <th style="text-align:right">Raw</th>
                    <th></th>
                </tr></thead><tbody>"#,
            );

            for attr in &cached.info.attributes {
                let (status_class, status_text) = match attr.status {
                    smart::AttributeStatus::Ok => ("smart-ok", "OK"),
                    smart::AttributeStatus::Warning => ("smart-warn", "⚠"),
                    smart::AttributeStatus::Failed => ("smart-fail", "✗"),
                };

                html.push_str(&format!(
                    r#"<tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td style="text-align:right">{}</td>
                        <td style="text-align:right">{}</td>
                        <td style="text-align:right">{}</td>
                        <td style="text-align:right;font-family:monospace">{}</td>
                        <td><span class="smart-badge {}">{}</span></td>
                    </tr>"#,
                    attr.id, attr.name, attr.value, attr.worst, attr.threshold, attr.raw_value, status_class, status_text
                ));
            }

            html.push_str("</tbody></table>");
            Html(html).into_response()
        }
        None => Html(
            "<p style=\"color: var(--pico-secondary);\">No cached data. Enable monitoring for this disk and wait for refresh.</p>"
                .to_string(),
        )
        .into_response(),
    }
}

async fn start_smart_test(Path((name, test_type)): Path<(String, String)>) -> impl IntoResponse {
    let device = format!("/dev/{}", name);

    let test = match test_type.as_str() {
        "short" => smart::TestType::Short,
        "long" => smart::TestType::Long,
        "conveyance" => smart::TestType::Conveyance,
        _ => smart::TestType::Short,
    };

    match smart::start_test(&device, test).await {
        Ok(_) => Html(format!(
            "<small style=\"color: var(--pico-ins-color);\">✅ {} test started on {}</small>",
            test_type, device
        ))
        .into_response(),
        Err(e) => Html(format!(
            "<small style=\"color: var(--pico-del-color);\">❌ {}</small>",
            e
        ))
        .into_response(),
    }
}

async fn btrfs_page(State(_state): State<Arc<WebState>>) -> impl IntoResponse {
    let btrfs_available = btrfs::is_available().await;

    let mounts: std::collections::HashMap<String, String> =
        tokio::fs::read_to_string("/proc/mounts")
            .await
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("btrfs"))
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    Some((parts[0].to_string(), parts[1].to_string()))
                } else {
                    None
                }
            })
            .collect();

    let filesystems = if btrfs_available {
        btrfs::list_filesystems()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|fs| {
                let total_size: u64 = fs.devices.iter().map(|d| d.size).sum();
                let mountpoint = fs
                    .devices
                    .first()
                    .and_then(|d| mounts.get(&d.path))
                    .cloned()
                    .unwrap_or_else(|| "not mounted".to_string());
                BtrfsInfo {
                    uuid: fs.uuid.clone(),
                    label: fs.label.clone().unwrap_or_else(|| "—".to_string()),
                    device_count: fs.devices.len(),
                    total_size: format_bytes(total_size),
                    data_profile: "—".to_string(), // Would need to parse from btrfs fi df
                    metadata_profile: "—".to_string(),
                    mountpoint,
                    devices: fs
                        .devices
                        .into_iter()
                        .map(|d| BtrfsDeviceInfo {
                            devid: d.devid,
                            path: d.path,
                            size_human: format_bytes(d.size),
                        })
                        .collect(),
                }
            })
            .collect()
    } else {
        vec![]
    };

    HtmlTemplate(BtrfsTemplate {
        active_page: "btrfs".to_string(),
        btrfs_available,
        filesystems,
    })
}

#[derive(Deserialize, Debug)]
struct CreateBtrfsForm {
    #[serde(default)]
    label: Option<String>,
    data_profile: String,
    metadata_profile: String,
    #[serde(default)]
    devices: String,
}

async fn create_btrfs(Form(form): Form<CreateBtrfsForm>) -> impl IntoResponse {
    let devices: Vec<String> = form
        .devices
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if devices.is_empty() {
        return HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create Btrfs Failed".to_string(),
            output: String::new(),
            error: "No devices selected".to_string(),
        });
    }

    let data_profile = match form.data_profile.as_str() {
        "single" => btrfs::BtrfsProfile::Single,
        "dup" => btrfs::BtrfsProfile::Dup,
        "raid0" => btrfs::BtrfsProfile::Raid0,
        "raid1" => btrfs::BtrfsProfile::Raid1,
        "raid1c3" => btrfs::BtrfsProfile::Raid1c3,
        "raid1c4" => btrfs::BtrfsProfile::Raid1c4,
        "raid5" => btrfs::BtrfsProfile::Raid5,
        "raid6" => btrfs::BtrfsProfile::Raid6,
        "raid10" => btrfs::BtrfsProfile::Raid10,
        _ => btrfs::BtrfsProfile::Single,
    };

    let metadata_profile = match form.metadata_profile.as_str() {
        "single" => btrfs::BtrfsProfile::Single,
        "dup" => btrfs::BtrfsProfile::Dup,
        "raid0" => btrfs::BtrfsProfile::Raid0,
        "raid1" => btrfs::BtrfsProfile::Raid1,
        "raid1c3" => btrfs::BtrfsProfile::Raid1c3,
        "raid1c4" => btrfs::BtrfsProfile::Raid1c4,
        "raid5" => btrfs::BtrfsProfile::Raid5,
        "raid6" => btrfs::BtrfsProfile::Raid6,
        "raid10" => btrfs::BtrfsProfile::Raid10,
        _ => btrfs::BtrfsProfile::Dup,
    };

    let label = form.label.filter(|l| !l.is_empty());
    let device_refs: Vec<&str> = devices.iter().map(|s| s.as_str()).collect();

    match btrfs::create(
        &device_refs,
        label.as_deref(),
        data_profile,
        metadata_profile,
    )
    .await
    {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Btrfs filesystem created successfully".to_string(),
            output: format!(
                "Created with {} data profile and {} device(s)",
                form.data_profile,
                devices.len()
            ),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create Btrfs Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize, Debug)]
struct BtrfsAddDeviceForm {
    mountpoint: String,
    device: String,
}

async fn btrfs_add_device(Form(form): Form<BtrfsAddDeviceForm>) -> impl IntoResponse {
    match btrfs::device_add(&form.device, &form.mountpoint).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Device added to Btrfs".to_string(),
            output: format!("Added {} to filesystem at {}", form.device, form.mountpoint),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Add Device Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize, Debug)]
struct FormatDiskForm {
    device: String,
    fstype: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    force: Option<String>,
}

async fn format_disk(Form(form): Form<FormatDiskForm>) -> impl IntoResponse {
    if !form.device.starts_with("/dev/") {
        return HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Format Failed".to_string(),
            output: String::new(),
            error: "Invalid device path".to_string(),
        });
    }

    let force = form.force.is_some();
    let label = form.label.filter(|l| !l.is_empty());

    match filesystem::format_device(&form.device, &form.fstype, label.as_deref(), force).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: format!("Device '{}' formatted successfully", form.device),
            output: format!("Formatted as {} filesystem", form.fstype),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Format Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn wipe_disk(Path(name): Path<String>) -> impl IntoResponse {
    let device = format!("/dev/{}", name);

    match filesystem::wipe_device(&device).await {
        Ok(_) => Html(format!(
            r#"<tr id="disk-{}">
                <td colspan="6">
                    <article class="feedback-success" style="margin: 0;">
                        <p style="margin: 0;">✅ Device '{}' wiped successfully. <a href="/storage/disks">Refresh page</a></p>
                    </article>
                </td>
            </tr>"#,
            name, device
        )).into_response(),
        Err(e) => Html(format!(
            r#"<tr id="disk-{}">
                <td colspan="6">
                    <article class="feedback-error" style="margin: 0;">
                        <p style="margin: 0;">❌ Failed to wipe '{}': {}</p>
                    </article>
                </td>
            </tr>"#,
            name, device, e
        )).into_response(),
    }
}

/// Scan for new disks (rescan SCSI buses)
async fn scan_disks() -> impl IntoResponse {
    let mut scanned = 0;
    if let Ok(mut entries) = tokio::fs::read_dir("/sys/class/scsi_host").await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let scan_path = entry.path().join("scan");
            if tokio::fs::write(&scan_path, "- - -").await.is_ok() {
                scanned += 1;
            }
        }
    }

    let _ = tokio::process::Command::new("udevadm")
        .args(["trigger", "--subsystem-match=block"])
        .output()
        .await;
    let _ = tokio::process::Command::new("udevadm")
        .args(["settle", "--timeout=5"])
        .output()
        .await;

    Html(format!(
        r#"<article class="feedback-success" style="margin-top: 1rem;">
            <p style="margin: 0;">🔍 Scanned {} SCSI hosts. <a href="/storage/disks">Refresh page</a> to see new disks.</p>
        </article>"#,
        scanned
    ))
}

#[derive(Deserialize)]
struct MountForm {
    device: String,
    mountpoint: String,
    #[serde(default)]
    fstype: Option<String>,
}

async fn mount_device(Form(form): Form<MountForm>) -> impl IntoResponse {
    let _ = tokio::fs::create_dir_all(&form.mountpoint).await;

    match filesystem::mount(&form.device, &form.mountpoint, form.fstype.as_deref()).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: format!("Mounted '{}' at '{}'", form.device, form.mountpoint),
            output: String::new(),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Mount Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize)]
struct UmountForm {
    mountpoint: String,
    #[serde(default)]
    force: Option<String>,
}

async fn umount_device(Form(form): Form<UmountForm>) -> impl IntoResponse {
    let result = if form.force.is_some() {
        filesystem::umount_lazy(&form.mountpoint).await
    } else {
        filesystem::umount(&form.mountpoint).await
    };

    match result {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: format!("Unmounted '{}'", form.mountpoint),
            output: String::new(),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Unmount Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize)]
struct DiskSlotForm {
    disk_id: String,
    slot: String,
    #[serde(default)]
    label: String,
}

async fn set_disk_slot(
    State(state): State<Arc<WebState>>,
    Form(form): Form<DiskSlotForm>,
) -> impl IntoResponse {
    use crate::state::DiskSlot;

    let slot_clone = form.slot.clone();
    let disk_id_clone = form.disk_id.clone();
    let label_clone = form.label.clone();

    let result = state
        .state_manager
        .update(move |nas_state| {
            nas_state
                .settings
                .disk_slots
                .retain(|s| s.disk_id != disk_id_clone);

            nas_state.settings.disk_slots.push(DiskSlot {
                slot: slot_clone,
                disk_id: disk_id_clone.clone(),
                label: label_clone,
            });

            nas_state.settings.disk_slots.sort_by(|a, b| {
                let a_num: Option<u32> = a.slot.parse().ok();
                let b_num: Option<u32> = b.slot.parse().ok();
                match (a_num, b_num) {
                    (Some(an), Some(bn)) => an.cmp(&bn),
                    _ => a.slot.cmp(&b.slot),
                }
            });
        })
        .await;

    if let Err(e) = result {
        return Html(format!(
            r##"<article class="feedback-error">
                ❌ Failed to save: {}
            </article>"##,
            e
        ));
    }

    Html(format!(
        r##"<article class="feedback-success">
            ✅ Slot {} saved
        </article>"##,
        form.slot
    ))
}

#[derive(Deserialize)]
struct RemoveDiskSlotForm {
    disk_id: String,
}

async fn remove_disk_slot(
    State(state): State<Arc<WebState>>,
    Form(form): Form<RemoveDiskSlotForm>,
) -> impl IntoResponse {
    let disk_id = form.disk_id.clone();

    let current_state = state.state_manager.get().await;
    let slot_exists = current_state
        .settings
        .disk_slots
        .iter()
        .any(|s| s.disk_id == disk_id);

    if !slot_exists {
        return Html(format!(
            r##"<article class="feedback-warning">
                ⚠️ No slot found for disk: {}
            </article>"##,
            disk_id
        ));
    }

    let disk_id_for_closure = disk_id.clone();

    let result = state
        .state_manager
        .update(move |nas_state| {
            nas_state
                .settings
                .disk_slots
                .retain(|s| s.disk_id != disk_id_for_closure);
        })
        .await;

    if let Err(e) = result {
        return Html(format!(
            r##"<article class="feedback-error">
                ❌ Failed to save: {}
            </article>"##,
            e
        ));
    }

    Html(
        r##"<article class="feedback-success">
        ✅ Slot removed
    </article>"##
            .to_string(),
    )
}

async fn zfs_page(State(_state): State<Arc<WebState>>) -> impl IntoResponse {
    let zfs_available = zfs::is_available().await;
    let pools = if zfs_available {
        let pool_list = zfs::list_pools().await.unwrap_or_default();
        let all_datasets = zfs::list_datasets().await.unwrap_or_default();
        let all_snapshots = zfs::list_snapshots().await.unwrap_or_default();

        let mut pool_infos = Vec::new();
        for p in pool_list {
            let pool_datasets: Vec<DatasetInfo> = all_datasets
                .iter()
                .filter(|d| d.name.starts_with(&p.name))
                .map(|d| DatasetInfo {
                    name: d.name.clone(),
                    used_human: format_bytes(d.used),
                    available_human: format_bytes(d.available),
                    mountpoint: opt_to_string(&d.mountpoint),
                })
                .collect();

            let pool_snapshots: Vec<SnapshotInfo> = all_snapshots
                .iter()
                .filter(|s| s.name.starts_with(&p.name))
                .map(|s| SnapshotInfo {
                    name: s.name.clone(),
                    used_human: format_bytes(s.used),
                    creation: s.creation.clone(),
                    mountpoint: s.mountpoint.clone(),
                })
                .collect();

            let scrub_in_progress = zfs::pool_status(&p.name)
                .await
                .map(|status| {
                    status
                        .scan
                        .as_ref()
                        .is_some_and(|s| s.contains("scrub in progress"))
                })
                .unwrap_or(false);

            pool_infos.push(PoolInfo {
                name: p.name,
                health: p.health,
                size_human: format_bytes(p.used_usable + p.available_usable),
                used_human: format_bytes(p.used_usable),
                free_human: format_bytes(p.available_usable),
                capacity: p.capacity,
                fragmentation: p.fragmentation,
                scrub_in_progress,
                datasets: pool_datasets,
                snapshots: pool_snapshots,
            });
        }
        pool_infos
    } else {
        vec![]
    };

    HtmlTemplate(ZfsTemplate {
        active_page: "zfs".to_string(),
        zfs_available,
        pools,
    })
}

async fn raid_page(State(_state): State<Arc<WebState>>) -> impl IntoResponse {
    let mdadm_available = mdadm::is_available().await;
    let arrays = if mdadm_available {
        mdadm::list_arrays()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|a| {
                let id = a.device.replace("/dev/", "");
                ArrayInfo {
                    id,
                    device: a.device,
                    level: a.level,
                    state: a.state,
                    device_count: a.device_count,
                    size_human: format_bytes(a.size),
                    rebuild_progress: a
                        .rebuild_progress
                        .map(|p| format!("{:.1}", p))
                        .unwrap_or_default(),
                    devices: a
                        .devices
                        .into_iter()
                        .map(|d| ArrayDeviceInfo {
                            path: d.path,
                            state: d.state,
                        })
                        .collect(),
                }
            })
            .collect()
    } else {
        vec![]
    };

    HtmlTemplate(RaidTemplate {
        active_page: "raid".to_string(),
        mdadm_available,
        arrays,
    })
}

async fn smb_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let config = state.state_manager.get_smb().await;
    let shares: Vec<SmbShareView> = config.shares.into_iter().map(Into::into).collect();
    HtmlTemplate(SmbTemplate {
        active_page: "smb".to_string(),
        smb_enabled: config.enabled,
        shares,
    })
}

async fn nfs_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let config = state.state_manager.get_nfs().await;
    let exports: Vec<NfsExportView> = config.exports.into_iter().map(Into::into).collect();
    HtmlTemplate(NfsTemplate {
        active_page: "nfs".to_string(),
        nfs_enabled: config.enabled,
        exports,
    })
}

async fn users_page() -> impl IntoResponse {
    HtmlTemplate(UsersListTemplate {
        active_page: "users".to_string(),
    })
}

async fn users_settings_page() -> impl IntoResponse {
    HtmlTemplate(UsersSettingsTemplate {
        active_page: "users-settings".to_string(),
    })
}

async fn groups_page() -> impl IntoResponse {
    HtmlTemplate(GroupsTemplate {
        active_page: "groups".to_string(),
    })
}

async fn ssh_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    HtmlTemplate(SshTemplate {
        active_page: "ssh".to_string(),
        ssh_enabled: nas_state.settings.ssh_enabled,
        ssh_port: nas_state.settings.ssh_port,
        permit_root_login: nas_state.settings.ssh_permit_root_login,
        password_auth: nas_state.settings.ssh_password_auth,
        pubkey_auth: nas_state.settings.ssh_pubkey_auth,
    })
}

async fn services_page() -> impl IntoResponse {
    HtmlTemplate(ServicesTemplate {
        active_page: "services".to_string(),
    })
}

async fn rsync_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    let modules: Vec<RsyncModuleView> = nas_state
        .rsync_modules
        .iter()
        .map(|m| RsyncModuleView {
            name: m.name.clone(),
            path: m.path.clone(),
            read_only: m.read_only,
        })
        .collect();

    HtmlTemplate(RsyncTemplate {
        active_page: "rsync".to_string(),
        rsync_enabled: nas_state.settings.rsync_enabled,
        modules,
    })
}

async fn system_page(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let gens = state.nix.list_generations().await.unwrap_or_default();
    let generations: Vec<GenerationInfo> = gens
        .into_iter()
        .map(|g| GenerationInfo {
            id: g.id,
            date: format!("{} {}", g.date, g.time),
            current: g.current,
        })
        .collect();

    HtmlTemplate(SystemTemplate {
        active_page: "system".to_string(),
        generations,
    })
}

#[derive(Deserialize, Debug)]
struct CreateZfsPoolForm {
    name: String,
    level: String,
    #[serde(default)]
    devices: String, // Comma-separated
    #[serde(default)]
    force: Option<String>,
    #[serde(default)]
    ashift: Option<String>,
    #[serde(default)]
    compression: Option<String>,
    #[serde(default)]
    autoexpand: Option<String>,
    #[serde(default)]
    atime_off: Option<String>,
    #[serde(default)]
    posix_acl: Option<String>,
    #[serde(default)]
    xattr_sa: Option<String>,
}

async fn create_zfs_pool(
    State(_state): State<Arc<WebState>>,
    Form(form): Form<CreateZfsPoolForm>,
) -> impl IntoResponse {
    let devices: Vec<String> = form
        .devices
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if devices.is_empty() {
        return HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create Pool Failed".to_string(),
            output: String::new(),
            error: "No devices selected".to_string(),
        });
    }

    let level = match form.level.as_str() {
        "mirror" => zfs::RaidLevel::Mirror,
        "raidz1" => zfs::RaidLevel::RaidZ1,
        "raidz2" => zfs::RaidLevel::RaidZ2,
        "raidz3" => zfs::RaidLevel::RaidZ3,
        _ => zfs::RaidLevel::Stripe,
    };

    let options = zfs::CreatePoolOptions {
        force: form.force.is_some(),
        ashift: form.ashift.as_ref().and_then(|s| s.parse().ok()),
        compression: form.compression.clone().filter(|s| !s.is_empty()),
        autoexpand: form.autoexpand.is_some(),
        atime_off: form.atime_off.is_some(),
        posix_acl: form.posix_acl.is_some(),
        xattr_sa: form.xattr_sa.is_some(),
    };

    let device_refs: Vec<&str> = devices.iter().map(|s| s.as_str()).collect();

    match zfs::create_pool(&form.name, level, &device_refs, options).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: format!("Pool '{}' created successfully", form.name),
            output: format!(
                "Created {} pool with {} device(s)",
                form.level,
                devices.len()
            ),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create Pool Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn delete_zfs_pool(Path(name): Path<String>) -> impl IntoResponse {
    match zfs::destroy_pool(&name, true).await {
        Ok(_) => Html(format!(
            r#"<article class="feedback-success">
                <p>✅ Pool '{}' destroyed successfully. <a href="/storage/zfs">Refresh page</a></p>
            </article>"#,
            name
        ))
        .into_response(),
        Err(e) => Html(format!(
            r#"<article class="feedback-error">
                <p>❌ Failed to destroy pool '{}': {}</p>
            </article>"#,
            name, e
        ))
        .into_response(),
    }
}

async fn export_zfs_pool(Path(name): Path<String>) -> impl IntoResponse {
    match zfs::export_pool(&name).await {
        Ok(_) => Html(format!(
            r#"<article class="feedback-success">
                <p>✅ Pool '{}' exported successfully. <a href="/storage/zfs">Refresh page</a></p>
            </article>"#,
            name
        ))
        .into_response(),
        Err(e) => Html(format!(
            r#"<article class="feedback-error">
                <p>❌ Failed to export pool '{}': {}</p>
            </article>"#,
            name, e
        ))
        .into_response(),
    }
}

async fn scrub_zfs_pool(Path(name): Path<String>) -> impl IntoResponse {
    match zfs::scrub_start(&name).await {
        Ok(_) => Html(format!(
            r#"<small style="color: var(--pico-ins-color);">✅ Scrub started on pool '{}'</small>"#,
            name
        ))
        .into_response(),
        Err(e) => Html(format!(
            r#"<small style="color: var(--pico-del-color);">❌ {}</small>"#,
            e
        ))
        .into_response(),
    }
}

async fn stop_scrub_zfs_pool(Path(name): Path<String>) -> impl IntoResponse {
    match zfs::scrub_stop(&name).await {
        Ok(_) => Html(format!(
            r#"<small style="color: var(--pico-ins-color);">✅ Scrub stopped on pool '{}'</small>"#,
            name
        ))
        .into_response(),
        Err(e) => Html(format!(
            r#"<small style="color: var(--pico-del-color);">❌ {}</small>"#,
            e
        ))
        .into_response(),
    }
}

async fn get_zfs_pool_properties(Path(name): Path<String>) -> impl IntoResponse {
    match zfs::get_pool_properties(&name).await {
        Ok(props) => {
            let mut html = format!(
                r##"<form hx-post="/api/web/zfs/pools/{}/properties" hx-target="#props-result" hx-swap="innerHTML">"##,
                name
            );
            html.push_str(r#"<table><thead><tr><th>Property</th><th>Value</th><th>Source</th></tr></thead><tbody>"#);

            let pool_editable = [
                "autoexpand",
                "autoreplace",
                "delegation",
                "failmode",
                "listsnapshots",
            ];

            for prop in &props {
                let is_editable = pool_editable.contains(&prop.name.as_str());
                html.push_str("<tr>");
                html.push_str(&format!("<td><code>{}</code></td>", prop.name));

                if is_editable {
                    if prop.value == "on" || prop.value == "off" {
                        html.push_str(&format!(
                            r#"<td><select name="{}" style="margin:0;padding:0.25rem;">
                                <option value="on" {}>on</option>
                                <option value="off" {}>off</option>
                            </select></td>"#,
                            prop.name,
                            if prop.value == "on" { "selected" } else { "" },
                            if prop.value == "off" { "selected" } else { "" }
                        ));
                    } else {
                        html.push_str(&format!(
                            r#"<td><input type="text" name="{}" value="{}" style="margin:0;padding:0.25rem;"></td>"#,
                            prop.name, prop.value
                        ));
                    }
                } else {
                    html.push_str(&format!("<td>{}</td>", prop.value));
                }

                html.push_str(&format!("<td><small>{}</small></td>", prop.source));
                html.push_str("</tr>");
            }

            html.push_str(r#"<tr><td colspan="3"><strong>Dataset Properties (inherited by children)</strong></td></tr>"#);

            let acltype = zfs::get_property(&name, "acltype")
                .await
                .unwrap_or_else(|_| "off".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>acltype</code></td>
                <td><select name="ds:acltype" style="margin:0;padding:0.25rem;">
                    <option value="off" {}>off</option>
                    <option value="posix" {}>posix</option>
                </select></td>
                <td><small>POSIX ACL support</small></td></tr>"#,
                if acltype == "off" { "selected" } else { "" },
                if acltype == "posix" || acltype == "posixacl" {
                    "selected"
                } else {
                    ""
                }
            ));

            let xattr = zfs::get_property(&name, "xattr")
                .await
                .unwrap_or_else(|_| "on".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>xattr</code></td>
                <td><select name="ds:xattr" style="margin:0;padding:0.25rem;">
                    <option value="off" {}>off</option>
                    <option value="on" {}>on</option>
                    <option value="sa" {}>sa (recommended)</option>
                </select></td>
                <td><small>Extended attributes</small></td></tr>"#,
                if xattr == "off" { "selected" } else { "" },
                if xattr == "on" { "selected" } else { "" },
                if xattr == "sa" { "selected" } else { "" }
            ));

            let compression = zfs::get_property(&name, "compression")
                .await
                .unwrap_or_else(|_| "off".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>compression</code></td>
                <td><select name="ds:compression" style="margin:0;padding:0.25rem;">
                    <option value="off" {}>off</option>
                    <option value="on" {}>on (lz4)</option>
                    <option value="lz4" {}>lz4</option>
                    <option value="lzjb" {}>lzjb</option>
                    <option value="zle" {}>zle</option>
                    <option value="gzip-1" {}>gzip-1</option>
                    <option value="gzip-2" {}>gzip-2</option>
                    <option value="gzip-3" {}>gzip-3</option>
                    <option value="gzip-4" {}>gzip-4</option>
                    <option value="gzip-5" {}>gzip-5</option>
                    <option value="gzip" {}>gzip (gzip-6)</option>
                    <option value="gzip-7" {}>gzip-7</option>
                    <option value="gzip-8" {}>gzip-8</option>
                    <option value="gzip-9" {}>gzip-9</option>
                    <option value="zstd-fast-1000" {}>zstd-fast-1000</option>
                    <option value="zstd-fast-500" {}>zstd-fast-500</option>
                    <option value="zstd-fast-100" {}>zstd-fast-100</option>
                    <option value="zstd-fast-90" {}>zstd-fast-90</option>
                    <option value="zstd-fast-80" {}>zstd-fast-80</option>
                    <option value="zstd-fast-70" {}>zstd-fast-70</option>
                    <option value="zstd-fast-60" {}>zstd-fast-60</option>
                    <option value="zstd-fast-50" {}>zstd-fast-50</option>
                    <option value="zstd-fast-40" {}>zstd-fast-40</option>
                    <option value="zstd-fast-30" {}>zstd-fast-30</option>
                    <option value="zstd-fast-20" {}>zstd-fast-20</option>
                    <option value="zstd-fast-10" {}>zstd-fast-10</option>
                    <option value="zstd-fast-9" {}>zstd-fast-9</option>
                    <option value="zstd-fast-8" {}>zstd-fast-8</option>
                    <option value="zstd-fast-7" {}>zstd-fast-7</option>
                    <option value="zstd-fast-6" {}>zstd-fast-6</option>
                    <option value="zstd-fast-5" {}>zstd-fast-5</option>
                    <option value="zstd-fast-4" {}>zstd-fast-4</option>
                    <option value="zstd-fast-3" {}>zstd-fast-3</option>
                    <option value="zstd-fast-2" {}>zstd-fast-2</option>
                    <option value="zstd-fast-1" {}>zstd-fast-1</option>
                    <option value="zstd-fast" {}>zstd-fast</option>
                    <option value="zstd-1" {}>zstd-1</option>
                    <option value="zstd-2" {}>zstd-2</option>
                    <option value="zstd" {}>zstd (zstd-3)</option>
                    <option value="zstd-4" {}>zstd-4</option>
                    <option value="zstd-5" {}>zstd-5</option>
                    <option value="zstd-6" {}>zstd-6</option>
                    <option value="zstd-7" {}>zstd-7</option>
                    <option value="zstd-8" {}>zstd-8</option>
                    <option value="zstd-9" {}>zstd-9</option>
                    <option value="zstd-10" {}>zstd-10</option>
                    <option value="zstd-11" {}>zstd-11</option>
                    <option value="zstd-12" {}>zstd-12</option>
                    <option value="zstd-13" {}>zstd-13</option>
                    <option value="zstd-14" {}>zstd-14</option>
                    <option value="zstd-15" {}>zstd-15</option>
                    <option value="zstd-16" {}>zstd-16</option>
                    <option value="zstd-17" {}>zstd-17</option>
                    <option value="zstd-18" {}>zstd-18</option>
                    <option value="zstd-19" {}>zstd-19</option>
                </select></td>
                <td><small>Compression algorithm</small></td></tr>"#,
                if compression == "off" { "selected" } else { "" },
                if compression == "on" { "selected" } else { "" },
                if compression == "lz4" { "selected" } else { "" },
                if compression == "lzjb" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zle" { "selected" } else { "" },
                if compression == "gzip-1" {
                    "selected"
                } else {
                    ""
                },
                if compression == "gzip-2" {
                    "selected"
                } else {
                    ""
                },
                if compression == "gzip-3" {
                    "selected"
                } else {
                    ""
                },
                if compression == "gzip-4" {
                    "selected"
                } else {
                    ""
                },
                if compression == "gzip-5" {
                    "selected"
                } else {
                    ""
                },
                if compression == "gzip" || compression == "gzip-6" {
                    "selected"
                } else {
                    ""
                },
                if compression == "gzip-7" {
                    "selected"
                } else {
                    ""
                },
                if compression == "gzip-8" {
                    "selected"
                } else {
                    ""
                },
                if compression == "gzip-9" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-1000" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-500" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-100" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-90" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-80" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-70" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-60" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-50" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-40" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-30" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-20" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-10" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-9" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-8" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-7" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-6" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-5" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-4" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-3" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-2" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast-1" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-fast" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-1" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-2" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd" || compression == "zstd-3" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-4" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-5" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-6" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-7" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-8" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-9" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-10" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-11" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-12" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-13" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-14" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-15" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-16" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-17" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-18" {
                    "selected"
                } else {
                    ""
                },
                if compression == "zstd-19" {
                    "selected"
                } else {
                    ""
                }
            ));

            let atime = zfs::get_property(&name, "atime")
                .await
                .unwrap_or_else(|_| "on".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>atime</code></td>
                <td><select name="ds:atime" style="margin:0;padding:0.25rem;">
                    <option value="on" {}>on</option>
                    <option value="off" {}>off</option>
                </select></td>
                <td><small>Access time updates</small></td></tr>"#,
                if atime == "on" { "selected" } else { "" },
                if atime == "off" { "selected" } else { "" }
            ));

            let relatime = zfs::get_property(&name, "relatime")
                .await
                .unwrap_or_else(|_| "on".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>relatime</code></td>
                <td><select name="ds:relatime" style="margin:0;padding:0.25rem;">
                    <option value="on" {}>on</option>
                    <option value="off" {}>off</option>
                </select></td>
                <td><small>Relative atime (reduces writes)</small></td></tr>"#,
                if relatime == "on" { "selected" } else { "" },
                if relatime == "off" { "selected" } else { "" }
            ));

            let checksum = zfs::get_property(&name, "checksum")
                .await
                .unwrap_or_else(|_| "on".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>checksum</code></td>
                <td><select name="ds:checksum" style="margin:0;padding:0.25rem;">
                    <option value="on" {}>on (fletcher4)</option>
                    <option value="off" {}>off (⚠️)</option>
                    <option value="fletcher4" {}>fletcher4</option>
                    <option value="sha256" {}>sha256</option>
                    <option value="sha512" {}>sha512</option>
                    <option value="skein" {}>skein</option>
                    <option value="edonr" {}>edonr</option>
                    <option value="blake3" {}>blake3</option>
                </select></td>
                <td><small>Data integrity checksum</small></td></tr>"#,
                if checksum == "on" { "selected" } else { "" },
                if checksum == "off" { "selected" } else { "" },
                if checksum == "fletcher4" {
                    "selected"
                } else {
                    ""
                },
                if checksum == "sha256" { "selected" } else { "" },
                if checksum == "sha512" { "selected" } else { "" },
                if checksum == "skein" { "selected" } else { "" },
                if checksum == "edonr" { "selected" } else { "" },
                if checksum == "blake3" { "selected" } else { "" }
            ));

            let dedup = zfs::get_property(&name, "dedup")
                .await
                .unwrap_or_else(|_| "off".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>dedup</code></td>
                <td><select name="ds:dedup" style="margin:0;padding:0.25rem;">
                    <option value="off" {}>off</option>
                    <option value="on" {}>on</option>
                    <option value="verify" {}>verify</option>
                </select></td>
                <td><small>Deduplication (⚠️ RAM intensive)</small></td></tr>"#,
                if dedup == "off" { "selected" } else { "" },
                if dedup == "on" { "selected" } else { "" },
                if dedup == "verify" { "selected" } else { "" }
            ));

            let sync = zfs::get_property(&name, "sync")
                .await
                .unwrap_or_else(|_| "standard".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>sync</code></td>
                <td><select name="ds:sync" style="margin:0;padding:0.25rem;">
                    <option value="standard" {}>standard</option>
                    <option value="always" {}>always</option>
                    <option value="disabled" {}>disabled (⚠️)</option>
                </select></td>
                <td><small>Synchronous writes</small></td></tr>"#,
                if sync == "standard" { "selected" } else { "" },
                if sync == "always" { "selected" } else { "" },
                if sync == "disabled" { "selected" } else { "" }
            ));

            let recordsize = zfs::get_property(&name, "recordsize")
                .await
                .unwrap_or_else(|_| "131072".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>recordsize</code></td>
                <td><select name="ds:recordsize" style="margin:0;padding:0.25rem;">
                    <option value="4096" {}>4K</option>
                    <option value="8192" {}>8K</option>
                    <option value="16384" {}>16K</option>
                    <option value="32768" {}>32K</option>
                    <option value="65536" {}>64K</option>
                    <option value="131072" {}>128K (default)</option>
                    <option value="262144" {}>256K</option>
                    <option value="524288" {}>512K</option>
                    <option value="1048576" {}>1M</option>
                </select></td>
                <td><small>Block size</small></td></tr>"#,
                if recordsize == "4096" || recordsize == "4K" {
                    "selected"
                } else {
                    ""
                },
                if recordsize == "8192" || recordsize == "8K" {
                    "selected"
                } else {
                    ""
                },
                if recordsize == "16384" || recordsize == "16K" {
                    "selected"
                } else {
                    ""
                },
                if recordsize == "32768" || recordsize == "32K" {
                    "selected"
                } else {
                    ""
                },
                if recordsize == "65536" || recordsize == "64K" {
                    "selected"
                } else {
                    ""
                },
                if recordsize == "131072" || recordsize == "128K" {
                    "selected"
                } else {
                    ""
                },
                if recordsize == "262144" || recordsize == "256K" {
                    "selected"
                } else {
                    ""
                },
                if recordsize == "524288" || recordsize == "512K" {
                    "selected"
                } else {
                    ""
                },
                if recordsize == "1048576" || recordsize == "1M" {
                    "selected"
                } else {
                    ""
                }
            ));

            let copies = zfs::get_property(&name, "copies")
                .await
                .unwrap_or_else(|_| "1".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>copies</code></td>
                <td><select name="ds:copies" style="margin:0;padding:0.25rem;">
                    <option value="1" {}>1</option>
                    <option value="2" {}>2</option>
                    <option value="3" {}>3</option>
                </select></td>
                <td><small>Data copies per block</small></td></tr>"#,
                if copies == "1" { "selected" } else { "" },
                if copies == "2" { "selected" } else { "" },
                if copies == "3" { "selected" } else { "" }
            ));

            let snapdir = zfs::get_property(&name, "snapdir")
                .await
                .unwrap_or_else(|_| "hidden".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>snapdir</code></td>
                <td><select name="ds:snapdir" style="margin:0;padding:0.25rem;">
                    <option value="hidden" {}>hidden</option>
                    <option value="visible" {}>visible</option>
                </select></td>
                <td><small>.zfs directory visibility</small></td></tr>"#,
                if snapdir == "hidden" { "selected" } else { "" },
                if snapdir == "visible" { "selected" } else { "" }
            ));

            let aclmode = zfs::get_property(&name, "aclmode")
                .await
                .unwrap_or_else(|_| "discard".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>aclmode</code></td>
                <td><select name="ds:aclmode" style="margin:0;padding:0.25rem;">
                    <option value="discard" {}>discard</option>
                    <option value="groupmask" {}>groupmask</option>
                    <option value="passthrough" {}>passthrough</option>
                    <option value="restricted" {}>restricted</option>
                </select></td>
                <td><small>ACL behavior on chmod</small></td></tr>"#,
                if aclmode == "discard" { "selected" } else { "" },
                if aclmode == "groupmask" {
                    "selected"
                } else {
                    ""
                },
                if aclmode == "passthrough" {
                    "selected"
                } else {
                    ""
                },
                if aclmode == "restricted" {
                    "selected"
                } else {
                    ""
                }
            ));

            let aclinherit = zfs::get_property(&name, "aclinherit")
                .await
                .unwrap_or_else(|_| "restricted".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>aclinherit</code></td>
                <td><select name="ds:aclinherit" style="margin:0;padding:0.25rem;">
                    <option value="discard" {}>discard</option>
                    <option value="noallow" {}>noallow</option>
                    <option value="restricted" {}>restricted</option>
                    <option value="passthrough" {}>passthrough</option>
                    <option value="passthrough-x" {}>passthrough-x</option>
                </select></td>
                <td><small>ACL inheritance</small></td></tr>"#,
                if aclinherit == "discard" {
                    "selected"
                } else {
                    ""
                },
                if aclinherit == "noallow" {
                    "selected"
                } else {
                    ""
                },
                if aclinherit == "restricted" {
                    "selected"
                } else {
                    ""
                },
                if aclinherit == "passthrough" {
                    "selected"
                } else {
                    ""
                },
                if aclinherit == "passthrough-x" {
                    "selected"
                } else {
                    ""
                }
            ));

            let primarycache = zfs::get_property(&name, "primarycache")
                .await
                .unwrap_or_else(|_| "all".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>primarycache</code></td>
                <td><select name="ds:primarycache" style="margin:0;padding:0.25rem;">
                    <option value="all" {}>all</option>
                    <option value="metadata" {}>metadata</option>
                    <option value="none" {}>none</option>
                </select></td>
                <td><small>ARC cache policy</small></td></tr>"#,
                if primarycache == "all" {
                    "selected"
                } else {
                    ""
                },
                if primarycache == "metadata" {
                    "selected"
                } else {
                    ""
                },
                if primarycache == "none" {
                    "selected"
                } else {
                    ""
                }
            ));

            let secondarycache = zfs::get_property(&name, "secondarycache")
                .await
                .unwrap_or_else(|_| "all".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>secondarycache</code></td>
                <td><select name="ds:secondarycache" style="margin:0;padding:0.25rem;">
                    <option value="all" {}>all</option>
                    <option value="metadata" {}>metadata</option>
                    <option value="none" {}>none</option>
                </select></td>
                <td><small>L2ARC cache policy</small></td></tr>"#,
                if secondarycache == "all" {
                    "selected"
                } else {
                    ""
                },
                if secondarycache == "metadata" {
                    "selected"
                } else {
                    ""
                },
                if secondarycache == "none" {
                    "selected"
                } else {
                    ""
                }
            ));

            let logbias = zfs::get_property(&name, "logbias")
                .await
                .unwrap_or_else(|_| "latency".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>logbias</code></td>
                <td><select name="ds:logbias" style="margin:0;padding:0.25rem;">
                    <option value="latency" {}>latency</option>
                    <option value="throughput" {}>throughput</option>
                </select></td>
                <td><small>SLOG optimization</small></td></tr>"#,
                if logbias == "latency" { "selected" } else { "" },
                if logbias == "throughput" {
                    "selected"
                } else {
                    ""
                }
            ));

            let dnodesize = zfs::get_property(&name, "dnodesize")
                .await
                .unwrap_or_else(|_| "legacy".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>dnodesize</code></td>
                <td><select name="ds:dnodesize" style="margin:0;padding:0.25rem;">
                    <option value="legacy" {}>legacy</option>
                    <option value="auto" {}>auto</option>
                    <option value="1k" {}>1K</option>
                    <option value="2k" {}>2K</option>
                    <option value="4k" {}>4K</option>
                    <option value="8k" {}>8K</option>
                    <option value="16k" {}>16K</option>
                </select></td>
                <td><small>Dnode size</small></td></tr>"#,
                if dnodesize == "legacy" {
                    "selected"
                } else {
                    ""
                },
                if dnodesize == "auto" { "selected" } else { "" },
                if dnodesize == "1k" { "selected" } else { "" },
                if dnodesize == "2k" { "selected" } else { "" },
                if dnodesize == "4k" { "selected" } else { "" },
                if dnodesize == "8k" { "selected" } else { "" },
                if dnodesize == "16k" { "selected" } else { "" }
            ));

            let redundant_metadata = zfs::get_property(&name, "redundant_metadata")
                .await
                .unwrap_or_else(|_| "all".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>redundant_metadata</code></td>
                <td><select name="ds:redundant_metadata" style="margin:0;padding:0.25rem;">
                    <option value="all" {}>all</option>
                    <option value="most" {}>most</option>
                    <option value="some" {}>some</option>
                    <option value="none" {}>none</option>
                </select></td>
                <td><small>Metadata redundancy</small></td></tr>"#,
                if redundant_metadata == "all" {
                    "selected"
                } else {
                    ""
                },
                if redundant_metadata == "most" {
                    "selected"
                } else {
                    ""
                },
                if redundant_metadata == "some" {
                    "selected"
                } else {
                    ""
                },
                if redundant_metadata == "none" {
                    "selected"
                } else {
                    ""
                }
            ));

            let prefetch = zfs::get_property(&name, "prefetch")
                .await
                .unwrap_or_else(|_| "all".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>prefetch</code></td>
                <td><select name="ds:prefetch" style="margin:0;padding:0.25rem;">
                    <option value="all" {}>all</option>
                    <option value="metadata" {}>metadata</option>
                    <option value="none" {}>none</option>
                </select></td>
                <td><small>Prefetch policy</small></td></tr>"#,
                if prefetch == "all" { "selected" } else { "" },
                if prefetch == "metadata" {
                    "selected"
                } else {
                    ""
                },
                if prefetch == "none" { "selected" } else { "" }
            ));

            let direct = zfs::get_property(&name, "direct")
                .await
                .unwrap_or_else(|_| "standard".to_string());
            html.push_str(&format!(
                r#"<tr><td><code>direct</code></td>
                <td><select name="ds:direct" style="margin:0;padding:0.25rem;">
                    <option value="standard" {}>standard</option>
                    <option value="always" {}>always</option>
                    <option value="disabled" {}>disabled</option>
                </select></td>
                <td><small>Direct I/O (2.3+)</small></td></tr>"#,
                if direct == "standard" { "selected" } else { "" },
                if direct == "always" { "selected" } else { "" },
                if direct == "disabled" { "selected" } else { "" }
            ));

            html.push_str("</tbody></table>");
            html.push_str(r#"<div id="props-result"></div>"#);
            html.push_str(r#"<button type="submit" class="small">Save Changes</button></form>"#);

            Html(html).into_response()
        }
        Err(e) => Html(format!(
            "<p style=\"color: var(--pico-del-color);\">Error: {}</p>",
            e
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct SetPropertyForm {
    #[serde(flatten)]
    properties: std::collections::HashMap<String, String>,
}

async fn set_zfs_pool_property(
    Path(name): Path<String>,
    Form(form): Form<SetPropertyForm>,
) -> impl IntoResponse {
    let pool_editable = [
        "autoexpand",
        "autoreplace",
        "delegation",
        "failmode",
        "listsnapshots",
    ];

    let dataset_editable = [
        "ds:acltype",
        "ds:xattr",
        "ds:compression",
        "ds:atime",
        "ds:relatime",
        "ds:checksum",
        "ds:dedup",
        "ds:sync",
        "ds:recordsize",
        "ds:copies",
        "ds:snapdir",
        "ds:aclmode",
        "ds:aclinherit",
        "ds:primarycache",
        "ds:secondarycache",
        "ds:logbias",
        "ds:dnodesize",
        "ds:redundant_metadata",
        "ds:prefetch",
        "ds:direct",
    ];

    let mut errors = Vec::new();
    let mut success = 0;

    for (prop, value) in form.properties.iter() {
        if pool_editable.contains(&prop.as_str()) {
            let current = zfs::get_pool_properties(&name)
                .await
                .ok()
                .and_then(|props| props.into_iter().find(|p| p.name == *prop))
                .map(|p| p.value)
                .unwrap_or_default();

            if current != *value {
                if let Err(e) = zfs::set_pool_property(&name, prop, value).await {
                    errors.push(format!("{}: {}", prop, e));
                } else {
                    success += 1;
                }
            }
        } else if dataset_editable.contains(&prop.as_str()) {
            let real_prop = prop.strip_prefix("ds:").unwrap_or(prop);

            let current = zfs::get_property(&name, real_prop)
                .await
                .unwrap_or_default();

            if current != *value {
                if let Err(e) = zfs::set_property(&name, real_prop, value).await {
                    errors.push(format!("{}: {}", real_prop, e));
                } else {
                    success += 1;
                }
            }
        }
    }

    if errors.is_empty() {
        Html(format!(
            r#"<small style="color: var(--pico-ins-color);">✅ {} properties updated</small>"#,
            success
        ))
        .into_response()
    } else {
        Html(format!(
            r#"<small style="color: var(--pico-del-color);">❌ Errors: {}</small>"#,
            errors.join(", ")
        ))
        .into_response()
    }
}

async fn get_importable_pools() -> impl IntoResponse {
    match zfs::list_importable().await {
        Ok(pools) => {
            if pools.is_empty() {
                return Html("<p>No importable pools found.</p>".to_string()).into_response();
            }

            let mut html = String::from(
                "<table><thead><tr><th>Pool</th><th>State</th><th>Action</th></tr></thead><tbody>",
            );

            for pool in pools {
                html.push_str(&format!(
                    r#"<tr>
                        <td><strong>{}</strong><br><small><code>{}</code></small></td>
                        <td>{}</td>
                        <td>
                            <form style="display: flex; gap: 0.5rem; align-items: center; margin: 0;"
                                  hx-post="/api/web/zfs/import/{}"
                                  hx-swap="outerHTML"
                                  hx-target="closest tr">
                                <label style="display: flex; align-items: center; gap: 0.25rem; font-size: 0.8rem; margin: 0;">
                                    <input type="checkbox" name="force" value="true" style="margin: 0;">
                                    Force
                                </label>
                                <button type="submit" class="small">📥 Import</button>
                            </form>
                        </td>
                    </tr>"#,
                    pool.name, pool.id, pool.state, pool.name
                ));
            }

            html.push_str("</tbody></table>");
            Html(html).into_response()
        }
        Err(e) => Html(format!(
            "<p style=\"color: var(--pico-del-color);\">Error: {}</p>",
            e
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct ImportPoolForm {
    #[serde(default)]
    force: Option<String>,
}

async fn import_zfs_pool(
    Path(name): Path<String>,
    Form(form): Form<ImportPoolForm>,
) -> impl IntoResponse {
    let force = form.force.is_some();
    match zfs::import_pool(&name, force).await {
        Ok(_) => Html(format!(
            r#"<tr class="row-success">
                <td colspan="3">✅ Pool '{}' imported successfully{}. <a href="/storage/zfs">Refresh page</a></td>
            </tr>"#,
            name,
            if force { " (forced)" } else { "" }
        )).into_response(),
        Err(e) => Html(format!(
            r#"<tr class="row-error">
                <td colspan="3">❌ Failed to import '{}': {}</td>
            </tr>"#,
            name, e
        )).into_response(),
    }
}

#[derive(Deserialize)]
struct CreateDatasetForm {
    pool: String,
    name: String,
    #[serde(default)]
    quota: Option<String>,
}

async fn create_zfs_dataset(Form(form): Form<CreateDatasetForm>) -> impl IntoResponse {
    let full_name = format!("{}/{}", form.pool, form.name);

    match zfs::create_dataset(&full_name, None).await {
        Ok(_) => {
            if let Some(ref quota) = form.quota
                && !quota.is_empty()
            {
                let _ = zfs::set_property(&full_name, "quota", quota).await;
            }
            HtmlTemplate(BuildOutputTemplate {
                success: true,
                title: format!("Dataset '{}' created", full_name),
                output: String::new(),
                error: String::new(),
            })
        }
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create Dataset Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn delete_zfs_dataset(Path(name): Path<String>) -> impl IntoResponse {
    // Wildcard captures include leading slash, strip it
    let name = name.strip_prefix('/').unwrap_or(&name);
    let decoded_name = urlencoding::decode(name).unwrap_or_else(|_| name.to_string().into());

    match zfs::destroy_dataset(&decoded_name, true).await {
        Ok(_) => Html(format!(
            r#"<tr class="row-success">
                <td colspan="5">✅ Dataset '{}' deleted</td>
            </tr>"#,
            decoded_name
        ))
        .into_response(),
        Err(e) => Html(format!(
            r#"<tr class="row-error">
                <td colspan="5">❌ {}</td>
            </tr>"#,
            e
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct CreateSnapshotForm {
    dataset: String,
    name: String,
}

async fn create_zfs_snapshot(Form(form): Form<CreateSnapshotForm>) -> impl IntoResponse {
    match zfs::create_snapshot(&form.dataset, &form.name).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: format!("Snapshot '{}@{}' created", form.dataset, form.name),
            output: String::new(),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create Snapshot Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn rollback_zfs_snapshot(Path(name): Path<String>) -> impl IntoResponse {
    // Wildcard captures include leading slash, strip it
    let name = name.strip_prefix('/').unwrap_or(&name);
    let decoded_name = urlencoding::decode(name).unwrap_or_else(|_| name.to_string().into());

    match zfs::rollback(&decoded_name, true).await {
        Ok(_) => Html(format!(
            r#"<article class="feedback-success">
                <p>✅ Rolled back to '{}'. <a href="/storage/zfs">Refresh page</a></p>
            </article>"#,
            decoded_name
        ))
        .into_response(),
        Err(e) => Html(format!(
            r#"<article class="feedback-error">
                <p>❌ Rollback failed: {}</p>
            </article>"#,
            e
        ))
        .into_response(),
    }
}

async fn delete_zfs_snapshot(Path(name): Path<String>) -> impl IntoResponse {
    // Wildcard captures include leading slash, strip it
    let name = name.strip_prefix('/').unwrap_or(&name);
    let decoded_name = urlencoding::decode(name).unwrap_or_else(|_| name.to_string().into());

    match zfs::destroy_snapshot(&decoded_name).await {
        Ok(_) => Html(
            r#"<tr class="row-success"><td colspan="4">✅ Snapshot deleted</td></tr>"#.to_string(),
        )
        .into_response(),
        Err(e) => Html(format!(
            r#"<tr class="row-error"><td colspan="4">❌ {}</td></tr>"#,
            e
        ))
        .into_response(),
    }
}

async fn mount_zfs_snapshot(Path(name): Path<String>) -> impl IntoResponse {
    // Wildcard captures include leading slash, strip it
    let name = name.strip_prefix('/').unwrap_or(&name);
    let decoded_name = urlencoding::decode(name).unwrap_or_else(|_| name.to_string().into());

    // Snapshot name format: pool/dataset@snapshot_name
    // We'll mount it to /mnt/snapshots/pool_dataset_snapshot_name
    let mount_name = decoded_name.replace(['/', '@'], "_");
    let mount_path = format!("/mnt/snapshots/{}", mount_name);

    if let Err(e) = tokio::fs::create_dir_all(&mount_path).await {
        return Html(format!(
            r##"<article class="feedback-error">
                ❌ Failed to create mount point: {}
            </article>"##,
            e
        ));
    }

    let check = tokio::process::Command::new("mountpoint")
        .arg("-q")
        .arg(&mount_path)
        .status()
        .await;

    if check.map(|s| s.success()).unwrap_or(false) {
        return Html(format!(
            r##"<article class="feedback-info">
                📂 Snapshot already mounted at: <code>{}</code><br>
                <small>Browse via SSH/terminal or file manager</small><br>
                <button class="small outline secondary" style="margin-top: 0.5rem;"
                        hx-post="/api/web/zfs/snapshots/unmount/{}"
                        hx-target="#snapshot-mount-result"
                        hx-swap="innerHTML">
                    🔓 Unmount
                </button>
            </article>"##,
            mount_path,
            urlencoding::encode(&decoded_name)
        ));
    }

    let result = tokio::process::Command::new("mount")
        .arg("-t")
        .arg("zfs")
        .arg("-o")
        .arg("ro")
        .arg(decoded_name.as_ref())
        .arg(&mount_path)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => Html(format!(
            r##"<article class="feedback-success">
                    ✅ Snapshot mounted (read-only) at: <code>{}</code><br>
                    <small>Browse via SSH/terminal or file manager</small><br>
                    <button class="small outline secondary" style="margin-top: 0.5rem;"
                            hx-post="/api/web/zfs/snapshots/unmount/{}"
                            hx-target="#snapshot-mount-result"
                            hx-swap="innerHTML">
                        🔓 Unmount
                    </button>
                </article>"##,
            mount_path,
            urlencoding::encode(&decoded_name)
        )),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _ = tokio::fs::remove_dir(&mount_path).await;
            Html(format!(
                r##"<article class="feedback-error">
                    ❌ Failed to mount snapshot: {}
                </article>"##,
                stderr
            ))
        }
        Err(e) => {
            let _ = tokio::fs::remove_dir(&mount_path).await;
            Html(format!(
                r##"<article class="feedback-error">
                    ❌ Mount command failed: {}
                </article>"##,
                e
            ))
        }
    }
}

async fn unmount_zfs_snapshot(Path(name): Path<String>) -> impl IntoResponse {
    // Wildcard captures include leading slash, strip it
    let name = name.strip_prefix('/').unwrap_or(&name);
    let decoded_name = urlencoding::decode(name).unwrap_or_else(|_| name.to_string().into());

    let mount_name = decoded_name.replace(['/', '@'], "_");
    let mount_path = format!("/mnt/snapshots/{}", mount_name);

    let result = tokio::process::Command::new("umount")
        .arg(&mount_path)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            let _ = tokio::fs::remove_dir(&mount_path).await;
            Html(
                r##"<article class="feedback-success">
                ✅ Snapshot unmounted successfully
            </article>"##
                    .to_string(),
            )
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Html(format!(
                r##"<article class="feedback-error">
                    ❌ Failed to unmount: {}
                </article>"##,
                stderr
            ))
        }
        Err(e) => Html(format!(
            r##"<article class="feedback-error">
                ❌ Unmount command failed: {}
            </article>"##,
            e
        )),
    }
}

async fn list_snapshot_policies(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let policies = state.state_manager.get_snapshot_policies().await;

    if policies.is_empty() {
        return Html(r#"<p style="color: var(--pico-muted-color); text-align: center;">No snapshot policies configured. Create one to enable automatic snapshots.</p>"#.to_string()).into_response();
    }

    let mut html = String::from(
        "<table><thead><tr><th>Name</th><th>Dataset</th><th>Schedule</th><th>Status</th><th>Actions</th></tr></thead><tbody>",
    );

    for policy in policies {
        let schedule = format!(
            "{}h/{}d/{}w/{}m/{}y",
            policy.hourly, policy.daily, policy.weekly, policy.monthly, policy.yearly
        );
        let status = if policy.enabled {
            "<span class=\"badge badge-success\">Active</span>"
        } else {
            "<span class=\"badge badge-warning\">Disabled</span>"
        };

        html.push_str(&format!(
            "<tr id=\"policy-{id}\">
                <td><strong>{name}</strong></td>
                <td><code>{dataset}</code>{recursive}</td>
                <td><small>{schedule}</small></td>
                <td>{status}</td>
                <td>
                    <div class=\"btn-group\">
                        <button class=\"small outline\"
                                hx-get=\"/api/web/zfs/policies/{id}/edit\"
                                hx-target=\"#policy-edit-form\"
                                hx-swap=\"innerHTML\"
                                onclick=\"document.getElementById('policy-edit-modal').showModal()\">
                            ✏️
                        </button>
                        <button class=\"small outline\"
                                hx-post=\"/api/web/zfs/policies/{id}/toggle\"
                                hx-target=\"#policy-{id}\"
                                hx-swap=\"outerHTML\">
                            {toggle_icon}
                        </button>
                        <button class=\"small outline secondary\"
                                hx-delete=\"/api/web/zfs/policies/{id}\"
                                hx-target=\"#policy-{id}\"
                                hx-swap=\"outerHTML\"
                                hx-confirm=\"Delete policy {name}?\">
                            🗑️
                        </button>
                    </div>
                </td>
            </tr>",
            id = policy.id,
            name = policy.name,
            dataset = policy.dataset,
            recursive = if policy.recursive {
                " <small>(recursive)</small>"
            } else {
                ""
            },
            schedule = schedule,
            status = status,
            toggle_icon = if policy.enabled { "⏸️" } else { "▶️" },
        ));
    }

    html.push_str("</tbody></table>");
    Html(html).into_response()
}

#[derive(Deserialize)]
struct CreatePolicyForm {
    name: String,
    dataset: String,
    #[serde(default)]
    recursive: Option<String>,
    #[serde(default)]
    hourly: Option<u32>,
    #[serde(default)]
    daily: Option<u32>,
    #[serde(default)]
    weekly: Option<u32>,
    #[serde(default)]
    monthly: Option<u32>,
    #[serde(default)]
    yearly: Option<u32>,
}

async fn create_snapshot_policy(
    State(state): State<Arc<WebState>>,
    Form(form): Form<CreatePolicyForm>,
) -> impl IntoResponse {
    let policy = SnapshotPolicy {
        id: uuid::Uuid::new_v4(),
        name: form.name.clone(),
        dataset: form.dataset,
        recursive: form.recursive.is_some(),
        enabled: true,
        hourly: form.hourly.unwrap_or(24),
        daily: form.daily.unwrap_or(7),
        weekly: form.weekly.unwrap_or(4),
        monthly: form.monthly.unwrap_or(12),
        yearly: form.yearly.unwrap_or(0),
    };

    match state.state_manager.add_snapshot_policy(policy).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: format!("Policy '{}' created", form.name),
            output: "Apply configuration to activate scheduled snapshots.".to_string(),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create Policy Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn update_snapshot_policy(
    State(state): State<Arc<WebState>>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<CreatePolicyForm>,
) -> impl IntoResponse {
    let policies = state.state_manager.get_snapshot_policies().await;
    let existing = policies.iter().find(|p| p.id == id);

    let policy = SnapshotPolicy {
        id,
        name: form.name.clone(),
        dataset: form.dataset,
        recursive: form.recursive.is_some(),
        enabled: existing.map(|p| p.enabled).unwrap_or(true),
        hourly: form.hourly.unwrap_or(24),
        daily: form.daily.unwrap_or(7),
        weekly: form.weekly.unwrap_or(4),
        monthly: form.monthly.unwrap_or(12),
        yearly: form.yearly.unwrap_or(0),
    };

    match state.state_manager.update_snapshot_policy(policy).await {
        Ok(_) => Html(format!(
            r##"<article class="feedback-success" style="margin: 0;">
                ✅ Policy '{}' updated successfully!
                <script>
                    setTimeout(function() {{
                        document.getElementById('policy-edit-modal').close();
                        htmx.trigger('#policies-list', 'refresh');
                    }}, 1000);
                </script>
            </article>"##,
            form.name
        )),
        Err(e) => Html(format!(
            r##"<article class="feedback-error" style="margin: 0;">
                ❌ Failed to update policy: {}
            </article>"##,
            e
        )),
    }
}

async fn get_policy_edit_form(
    State(state): State<Arc<WebState>>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    let policies = state.state_manager.get_snapshot_policies().await;

    if let Some(policy) = policies.into_iter().find(|p| p.id == id) {
        Html(format!(
            r##"<form hx-put="/api/web/zfs/policies/{id}"
                      hx-target="#policy-edit-result"
                      hx-swap="innerHTML">
                <input type="hidden" name="id" value="{id}">

                <label>Policy Name
                    <input type="text" name="name" value="{name}" required>
                </label>

                <label>Dataset
                    <input type="text" name="dataset" value="{dataset}" required readonly>
                    <small>Dataset cannot be changed. Delete and recreate if needed.</small>
                </label>

                <label>
                    <input type="checkbox" name="recursive" {recursive_checked}>
                    Recursive (include child datasets)
                </label>

                <h4 style="margin-top: 1rem;">Retention (snapshots to keep)</h4>
                <div class="retention-grid">
                    <label>Hourly
                        <input type="number" name="hourly" value="{hourly}" min="0" max="168">
                    </label>
                    <label>Daily
                        <input type="number" name="daily" value="{daily}" min="0" max="90">
                    </label>
                    <label>Weekly
                        <input type="number" name="weekly" value="{weekly}" min="0" max="52">
                    </label>
                    <label>Monthly
                        <input type="number" name="monthly" value="{monthly}" min="0" max="24">
                    </label>
                    <label>Yearly
                        <input type="number" name="yearly" value="{yearly}" min="0" max="10">
                    </label>
                </div>

                <div id="policy-edit-result" style="margin-top: 1rem;"></div>

                <footer style="margin-top: 1rem;">
                    <button type="button" class="secondary" onclick="document.getElementById('policy-edit-modal').close()">Cancel</button>
                    <button type="submit">Save Changes</button>
                </footer>
            </form>"##,
            id = policy.id,
            name = policy.name,
            dataset = policy.dataset,
            recursive_checked = if policy.recursive { "checked" } else { "" },
            hourly = policy.hourly,
            daily = policy.daily,
            weekly = policy.weekly,
            monthly = policy.monthly,
            yearly = policy.yearly,
        ))
    } else {
        Html("<p>Policy not found</p>".to_string())
    }
}

async fn toggle_snapshot_policy(
    State(state): State<Arc<WebState>>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    let policies = state.state_manager.get_snapshot_policies().await;

    if let Some(mut policy) = policies.into_iter().find(|p| p.id == id) {
        policy.enabled = !policy.enabled;
        let is_enabled = policy.enabled;
        let name = policy.name.clone();
        let dataset = policy.dataset.clone();
        let recursive = policy.recursive;
        let schedule = format!(
            "{}h/{}d/{}w/{}m/{}y",
            policy.hourly, policy.daily, policy.weekly, policy.monthly, policy.yearly
        );

        match state.state_manager.update_snapshot_policy(policy).await {
            Ok(_) => {
                let status = if is_enabled {
                    "<span class=\"badge badge-success\">Active</span>"
                } else {
                    "<span class=\"badge badge-warning\">Disabled</span>"
                };

                Html(format!(
                    "<tr id=\"policy-{id}\">
                        <td><strong>{name}</strong></td>
                        <td><code>{dataset}</code>{recursive}</td>
                        <td><small>{schedule}</small></td>
                        <td>{status}</td>
                        <td>
                            <div class=\"btn-group\">
                                <button class=\"small outline\"
                                        hx-get=\"/api/web/zfs/policies/{id}/edit\"
                                        hx-target=\"#policy-edit-form\"
                                        hx-swap=\"innerHTML\"
                                        onclick=\"document.getElementById('policy-edit-modal').showModal()\">
                                    ✏️
                                </button>
                                <button class=\"small outline\"
                                        hx-post=\"/api/web/zfs/policies/{id}/toggle\"
                                        hx-target=\"#policy-{id}\"
                                        hx-swap=\"outerHTML\">
                                    {toggle_icon}
                                </button>
                                <button class=\"small outline secondary\"
                                        hx-delete=\"/api/web/zfs/policies/{id}\"
                                        hx-target=\"#policy-{id}\"
                                        hx-swap=\"outerHTML\"
                                        hx-confirm=\"Delete policy {name}?\">
                                    🗑️
                                </button>
                            </div>
                        </td>
                    </tr>",
                    id = id,
                    name = name,
                    dataset = dataset,
                    recursive = if recursive {
                        " <small>(recursive)</small>"
                    } else {
                        ""
                    },
                    schedule = schedule,
                    status = status,
                    toggle_icon = if is_enabled { "⏸️" } else { "▶️" },
                ))
                .into_response()
            }
            Err(e) => Html(format!(
                r#"<tr><td colspan="5" style="color: var(--pico-del-color);">❌ {}</td></tr>"#,
                e
            ))
            .into_response(),
        }
    } else {
        Html(r#"<tr><td colspan="5" style="color: var(--pico-del-color);">❌ Policy not found</td></tr>"#.to_string()).into_response()
    }
}

async fn delete_snapshot_policy(
    State(state): State<Arc<WebState>>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    match state.state_manager.delete_snapshot_policy(id).await {
        Ok(_) => Html(
            r#"<tr class="row-success"><td colspan="5">✅ Policy deleted</td></tr>"#.to_string(),
        )
        .into_response(),
        Err(e) => Html(format!(
            r#"<tr class="row-error"><td colspan="5">❌ {}</td></tr>"#,
            e
        ))
        .into_response(),
    }
}

async fn get_zfs_settings(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let settings = state.state_manager.get().await.zfs_settings;

    let scrub_checked = if settings.auto_scrub_enable {
        "checked"
    } else {
        ""
    };
    let sel_weekly = if settings.auto_scrub_interval == "weekly" {
        "selected"
    } else {
        ""
    };
    let sel_monthly = if settings.auto_scrub_interval == "monthly" {
        "selected"
    } else {
        ""
    };
    let sel_biweekly = if settings.auto_scrub_interval.contains("1,15") {
        "selected"
    } else {
        ""
    };
    let sel_daily = if settings.auto_scrub_interval == "daily" {
        "selected"
    } else {
        ""
    };
    let sel_quarterly = if settings.auto_scrub_interval == "quarterly" {
        "selected"
    } else {
        ""
    };
    let is_custom = !["weekly", "monthly", "daily", "quarterly"]
        .contains(&settings.auto_scrub_interval.as_str())
        && !settings.auto_scrub_interval.contains("1,15");
    let sel_custom = if is_custom { "selected" } else { "" };
    let custom_interval = if is_custom {
        settings.auto_scrub_interval.clone()
    } else {
        String::new()
    };
    let custom_display = if is_custom { "block" } else { "none" };
    let scrub_pools = settings.auto_scrub_pools.join(" ");
    let trim_checked = if settings.trim_enable { "checked" } else { "" };
    let arc_max_gb = settings.arc_max_gb;
    let extra_pools = settings.extra_pools.join(" ");
    let force_checked = if settings.force_import_all {
        "checked"
    } else {
        ""
    };

    let dev_nodes_value = settings.dev_nodes.as_deref().unwrap_or("");
    let sel_dev_default = if dev_nodes_value.is_empty() {
        "selected"
    } else {
        ""
    };
    let sel_dev_by_id = if dev_nodes_value == "/dev/disk/by-id" {
        "selected"
    } else {
        ""
    };
    let sel_dev_by_path = if dev_nodes_value == "/dev/disk/by-path" {
        "selected"
    } else {
        ""
    };
    let sel_dev_by_partuuid = if dev_nodes_value == "/dev/disk/by-partuuid" {
        "selected"
    } else {
        ""
    };

    Html(format!(
        r##"<form hx-post="/api/web/zfs/settings" hx-target="#zfs-settings-result" hx-swap="innerHTML">
            <fieldset>
                <legend>📥 Pool Import</legend>
                <label>
                    Extra pools to import at boot
                    <input type="text" name="extra_pools" value="{extra_pools}" placeholder="pool1 pool2">
                    <small>Pools with datasets in fileSystems are auto-imported. Only add extra pools here.</small>
                </label>
                <label>
                    Device nodes path
                    <select name="dev_nodes">
                        <option value="" {sel_dev_default}>Default (/dev/disk/by-id)</option>
                        <option value="/dev/disk/by-id" {sel_dev_by_id}>/dev/disk/by-id</option>
                        <option value="/dev/disk/by-path" {sel_dev_by_path}>/dev/disk/by-path (VMs)</option>
                        <option value="/dev/disk/by-partuuid" {sel_dev_by_partuuid}>/dev/disk/by-partuuid</option>
                    </select>
                    <small>Use <code>/dev/disk/by-path</code> for VMs if pools fail to import at boot.</small>
                </label>
                <label>
                    <input type="checkbox" name="force_import_all" value="true" {force_checked}>
                    Force import (ignore "in use by another system" errors)
                </label>
            </fieldset>
            <fieldset>
                <legend>🔍 Auto Scrub</legend>
                <label>
                    <input type="checkbox" name="auto_scrub_enable" value="true" {scrub_checked}>
                    Enable automatic scrubbing
                </label>
                <small>Scrubs verify data integrity. Recommended for production pools.</small>
                <div class="grid">
                    <label>
                        Interval
                        <select name="auto_scrub_interval" onchange="toggleCustomInterval(this)">
                            <option value="weekly" {sel_weekly}>Weekly (Sun 02:00)</option>
                            <option value="monthly" {sel_monthly}>Monthly (1st 02:00)</option>
                            <option value="Sun *-*-1,15 02:00:00" {sel_biweekly}>Bi-weekly (1st & 15th)</option>
                            <option value="daily" {sel_daily}>Daily (02:00)</option>
                            <option value="quarterly" {sel_quarterly}>Quarterly</option>
                            <option value="custom" {sel_custom}>Custom...</option>
                        </select>
                        <small>Systemd calendar expression. See systemd.time(7)</small>
                    </label>
                    <label>
                        Pools (empty = all)
                        <input type="text" name="auto_scrub_pools" value="{scrub_pools}" placeholder="pool1 pool2">
                        <small>Space-separated pool names</small>
                    </label>
                </div>
                <div id="custom-interval-wrapper" style="display: {custom_display};">
                    <label>
                        Custom Interval
                        <input type="text" name="custom_interval" value="{custom_interval}" placeholder="Sun *-*-* 02:00:00">
                        <small>Examples: "Mon *-*-* 02:00:00", "*-*-01,15 03:00:00", "weekly"</small>
                    </label>
                </div>
            </fieldset>
            <fieldset>
                <legend>💾 Auto TRIM (SSDs)</legend>
                <label>
                    <input type="checkbox" name="trim_enable" value="true" {trim_checked}>
                    Enable automatic TRIM (enabled by default in NixOS)
                </label>
                <small>TRIM improves SSD performance and longevity. Keep enabled for SSD pools.</small>
            </fieldset>
            <fieldset>
                <legend>🧠 Memory (ARC Cache)</legend>
                <label>
                    Maximum ARC size (GB)
                    <input type="number" name="arc_max_gb" value="{arc_max_gb}" min="0" max="1024" placeholder="0">
                    <small>0 = Auto (ZFS uses up to 50% of RAM). Recommended: leave 4-8 GB free for system/apps.</small>
                </label>
                <small>Example: On 16 GB system, set to 8-12 GB. Requires reboot to apply.</small>
            </fieldset>
            <button type="submit">💾 Save Settings</button>
        </form>
        <script>
        function toggleCustomInterval(select) {{
            var wrapper = document.getElementById('custom-interval-wrapper');
            wrapper.style.display = select.value === 'custom' ? 'block' : 'none';
        }}
        </script>
        <div id="zfs-settings-result"></div>"##
    ))
}

#[derive(Deserialize)]
struct ZfsSettingsForm {
    #[serde(default)]
    auto_scrub_enable: Option<String>,
    #[serde(default)]
    auto_scrub_interval: String,
    #[serde(default)]
    custom_interval: String,
    #[serde(default)]
    auto_scrub_pools: String,
    #[serde(default)]
    trim_enable: Option<String>,
    #[serde(default)]
    trim_interval: String,
    #[serde(default)]
    extra_pools: String,
    #[serde(default)]
    force_import_all: Option<String>,
    #[serde(default)]
    dev_nodes: String,
    #[serde(default)]
    arc_max_gb: u32,
}

async fn update_zfs_settings(
    State(state): State<Arc<WebState>>,
    Form(form): Form<ZfsSettingsForm>,
) -> impl IntoResponse {
    let scrub_interval = if form.auto_scrub_interval == "custom" && !form.custom_interval.is_empty()
    {
        form.custom_interval
    } else {
        form.auto_scrub_interval
    };

    let settings = ZfsSettings {
        auto_scrub_enable: form.auto_scrub_enable.is_some(),
        auto_scrub_pools: form
            .auto_scrub_pools
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
        auto_scrub_interval: scrub_interval,
        trim_enable: form.trim_enable.is_some(),
        trim_interval: if form.trim_interval.is_empty() {
            "weekly".to_string()
        } else {
            form.trim_interval
        },
        extra_pools: form
            .extra_pools
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
        force_import_all: form.force_import_all.is_some(),
        dev_nodes: if form.dev_nodes.is_empty() {
            None
        } else {
            Some(form.dev_nodes)
        },
        arc_max_gb: form.arc_max_gb,
    };

    let _ = state
        .state_manager
        .update(|s| {
            s.zfs_settings = settings;
            s.pending_changes = true;
        })
        .await;

    let _ = state.nix.generate_all().await;

    let message = if form.arc_max_gb > 0 {
        "ZFS settings updated. Apply changes to activate. ⚠️ ARC size changes require a reboot."
    } else {
        "ZFS settings updated. Apply changes to activate."
    };

    HtmlTemplate(BuildOutputTemplate {
        success: true,
        title: "Settings Saved".to_string(),
        output: message.to_string(),
        error: String::new(),
    })
}

#[derive(Deserialize, Debug)]
struct CreateMdadmArrayForm {
    device: String,
    level: String,
    #[serde(default)]
    devices: String, // Comma-separated
}

async fn create_mdadm_array(
    State(_state): State<Arc<WebState>>,
    Form(form): Form<CreateMdadmArrayForm>,
) -> impl IntoResponse {
    let devices: Vec<String> = form
        .devices
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if devices.is_empty() {
        return HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create Array Failed".to_string(),
            output: String::new(),
            error: "No devices selected".to_string(),
        });
    }

    let level = match form.level.as_str() {
        "raid0" => mdadm::RaidLevel::Raid0,
        "raid1" => mdadm::RaidLevel::Raid1,
        "raid5" => mdadm::RaidLevel::Raid5,
        "raid6" => mdadm::RaidLevel::Raid6,
        "raid10" => mdadm::RaidLevel::Raid10,
        _ => mdadm::RaidLevel::Raid1,
    };

    let device_refs: Vec<&str> = devices.iter().map(|s| s.as_str()).collect();

    match mdadm::create_array(&form.device, level, &device_refs, &[]).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: format!("Array '{}' created successfully", form.device),
            output: format!(
                "Created {} array with {} device(s)",
                form.level,
                devices.len()
            ),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create Array Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn delete_mdadm_array(Path(name): Path<String>) -> impl IntoResponse {
    let device = if name.starts_with("/dev/") {
        name.clone()
    } else {
        format!("/dev/{}", name)
    };

    match mdadm::stop_array(&device).await {
        Ok(_) => Html(format!(
            r#"<article class="feedback-success">
                <p>✅ Array '{}' stopped successfully. <a href="/storage/raid">Refresh page</a></p>
            </article>"#,
            device
        ))
        .into_response(),
        Err(e) => Html(format!(
            r#"<article class="feedback-error">
                <p>❌ Failed to stop array '{}': {}</p>
            </article>"#,
            device, e
        ))
        .into_response(),
    }
}

#[derive(Deserialize, Debug)]
struct MdadmAddDeviceForm {
    device: String,
}

async fn mdadm_add_device(
    Path(name): Path<String>,
    Form(form): Form<MdadmAddDeviceForm>,
) -> impl IntoResponse {
    let array = if name.starts_with("/dev/") {
        name.clone()
    } else {
        format!("/dev/{}", name)
    };

    match mdadm::add_device(&array, &form.device).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Device Added".to_string(),
            output: format!("Added {} to array {}", form.device, array),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Add Device Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize, Debug)]
struct MdadmGrowForm {
    raid_devices: Option<u32>,
}

async fn mdadm_grow_array(
    Path(name): Path<String>,
    Form(form): Form<MdadmGrowForm>,
) -> impl IntoResponse {
    let array = if name.starts_with("/dev/") {
        name.clone()
    } else {
        format!("/dev/{}", name)
    };

    match mdadm::grow_array(&array, form.raid_devices, None).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Array Growing".to_string(),
            output: format!(
                "Growing array {} to {} devices",
                array,
                form.raid_devices.unwrap_or(0)
            ),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Grow Array Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize, Debug)]
struct ZfsAddVdevForm {
    devices: String,
    level: String,
    #[serde(default)]
    force: Option<String>,
}

async fn zfs_add_vdev(
    Path(name): Path<String>,
    Form(form): Form<ZfsAddVdevForm>,
) -> impl IntoResponse {
    let devices: Vec<String> = form
        .devices
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if devices.is_empty() {
        return HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Add Vdev Failed".to_string(),
            output: String::new(),
            error: "No devices specified".to_string(),
        });
    }

    let level = match form.level.as_str() {
        "stripe" => zfs::RaidLevel::Stripe,
        "mirror" => zfs::RaidLevel::Mirror,
        "raidz1" => zfs::RaidLevel::RaidZ1,
        "raidz2" => zfs::RaidLevel::RaidZ2,
        "raidz3" => zfs::RaidLevel::RaidZ3,
        _ => zfs::RaidLevel::Stripe,
    };

    let device_refs: Vec<&str> = devices.iter().map(|s| s.as_str()).collect();
    let force = form.force.is_some();

    match zfs::add_vdev(&name, level, &device_refs, force).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Vdev Added".to_string(),
            output: format!(
                "Added {} vdev with {} device(s) to pool {}",
                form.level,
                devices.len(),
                name
            ),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Add Vdev Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize, Debug)]
struct ZfsAddSpecialForm {
    device: String,
}

async fn zfs_add_spare(
    Path(name): Path<String>,
    Form(form): Form<ZfsAddSpecialForm>,
) -> impl IntoResponse {
    match zfs::add_spare(&name, &form.device).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Spare Added".to_string(),
            output: format!("Added {} as spare to pool {}", form.device, name),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Add Spare Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn zfs_add_cache(
    Path(name): Path<String>,
    Form(form): Form<ZfsAddSpecialForm>,
) -> impl IntoResponse {
    match zfs::add_cache(&name, &form.device).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Cache Added".to_string(),
            output: format!("Added {} as L2ARC cache to pool {}", form.device, name),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Add Cache Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize, Debug)]
struct ZfsAttachForm {
    existing_device: String,
    new_device: String,
    #[serde(default)]
    force: Option<String>,
}

async fn zfs_attach_device(
    Path(name): Path<String>,
    Form(form): Form<ZfsAttachForm>,
) -> impl IntoResponse {
    let force = form.force.is_some();

    match zfs::attach_device(&name, &form.existing_device, &form.new_device, force).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Device Attached".to_string(),
            output: format!(
                "Attached {} to {} in pool {} - resilvering started",
                form.new_device, form.existing_device, name
            ),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Attach Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize, Debug)]
struct ZfsReplaceForm {
    old_device: String,
    new_device: String,
    #[serde(default)]
    force: Option<String>,
}

async fn zfs_replace_device(
    Path(name): Path<String>,
    Form(form): Form<ZfsReplaceForm>,
) -> impl IntoResponse {
    let force = form.force.is_some();

    match zfs::replace_device(&name, &form.old_device, &form.new_device, force).await {
        Ok(_) => HtmlTemplate(BuildOutputTemplate {
            success: true,
            title: "Device Replace Started".to_string(),
            output: format!(
                "Replacing {} with {} in pool {} - resilver in progress",
                form.old_device, form.new_device, name
            ),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Replace Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

#[derive(Deserialize)]
struct CreateShareForm {
    name: String,
    path: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    guest_ok: Option<String>,
    #[serde(default)]
    guest_only: Option<String>,
    #[serde(default)]
    read_only: Option<String>,
    #[serde(default)]
    browseable: Option<String>,
    #[serde(default)]
    valid_users: Option<String>,
    #[serde(default)]
    invalid_users: Option<String>,
    #[serde(default)]
    write_list: Option<String>,
    #[serde(default)]
    read_list: Option<String>,
    #[serde(default)]
    force_user: Option<String>,
    #[serde(default)]
    force_group: Option<String>,
    #[serde(default)]
    create_mask: Option<String>,
    #[serde(default)]
    directory_mask: Option<String>,
    #[serde(default)]
    force_create_mode: Option<String>,
    #[serde(default)]
    force_directory_mode: Option<String>,
    #[serde(default)]
    inherit_acls: Option<String>,
    #[serde(default)]
    inherit_permissions: Option<String>,
    #[serde(default)]
    ea_support: Option<String>,
    #[serde(default)]
    store_dos_attributes: Option<String>,
    #[serde(default)]
    hide_dot_files: Option<String>,
    #[serde(default)]
    hide_special_files: Option<String>,
    #[serde(default)]
    follow_symlinks: Option<String>,
    #[serde(default)]
    wide_links: Option<String>,
    #[serde(default)]
    vfs_objects: Option<String>,
    #[serde(default)]
    time_machine: Option<String>,
    #[serde(default)]
    hosts_allow: Option<String>,
    #[serde(default)]
    hosts_deny: Option<String>,
    #[serde(default)]
    recycle_bin: Option<String>,
    #[serde(default)]
    recycle_max_size: Option<String>,
    #[serde(default)]
    recycle_retention_days: Option<String>,
    #[serde(default)]
    audit_enabled: Option<String>,
    #[serde(default)]
    smb_encrypt: Option<String>,
    #[serde(default)]
    extra_options: Option<String>,
}

fn parse_user_list(input: &Option<String>) -> Vec<String> {
    input
        .as_ref()
        .map(|s| s.split_whitespace().map(|u| u.to_string()).collect())
        .unwrap_or_default()
}

fn parse_optional_string(input: &Option<String>) -> Option<String> {
    input
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
}

async fn create_smb_share(
    State(state): State<Arc<WebState>>,
    Form(form): Form<CreateShareForm>,
) -> impl IntoResponse {
    let valid_users = parse_user_list(&form.valid_users);
    let write_list = parse_user_list(&form.write_list);

    let mut share = SmbShare::new(form.name, form.path.clone());
    share.id = Uuid::new_v4();
    share.comment = form.comment.unwrap_or_default();
    share.guest_ok = form.guest_ok.is_some();
    share.guest_only = form.guest_only.is_some();
    share.read_only = form.read_only.is_some();
    share.browseable = form.browseable.is_some();
    share.valid_users = valid_users;
    share.invalid_users = parse_user_list(&form.invalid_users);
    share.write_list = write_list;
    share.read_list = parse_user_list(&form.read_list);
    share.force_user = parse_optional_string(&form.force_user);
    share.force_group = parse_optional_string(&form.force_group);
    if let Some(ref mask) = form.create_mask
        && !mask.is_empty()
    {
        share.create_mask = mask.clone();
    }
    if let Some(ref mask) = form.directory_mask
        && !mask.is_empty()
    {
        share.directory_mask = mask.clone();
    }
    share.force_create_mode = parse_optional_string(&form.force_create_mode);
    share.force_directory_mode = parse_optional_string(&form.force_directory_mode);
    share.inherit_acls = form.inherit_acls.is_some();
    share.inherit_permissions = form.inherit_permissions.is_some();
    share.ea_support = form.ea_support.is_some();
    share.store_dos_attributes = form.store_dos_attributes.is_some();
    share.hide_dot_files = form.hide_dot_files.is_some();
    share.hide_special_files = form.hide_special_files.is_some();
    share.follow_symlinks = form.follow_symlinks.is_some();
    share.wide_links = form.wide_links.is_some();
    share.vfs_objects = parse_user_list(&form.vfs_objects);
    share.time_machine = form.time_machine.is_some();
    share.hosts_allow = parse_user_list(&form.hosts_allow);
    share.hosts_deny = parse_user_list(&form.hosts_deny);
    share.recycle_bin = form.recycle_bin.is_some();
    share.recycle_max_size = form
        .recycle_max_size
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    share.recycle_retention_days = form
        .recycle_retention_days
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    share.audit_enabled = form.audit_enabled.is_some();
    share.smb_encrypt = form
        .smb_encrypt
        .clone()
        .unwrap_or_else(|| "auto".to_string());
    share.extra_options = form.extra_options.clone().unwrap_or_default();

    if let Err(e) = create_share_directory(&share.path).await {
        tracing::warn!("Failed to setup share directory: {}", e);
    }

    let share_view: SmbShareView = share.clone().into();
    match state.smb.create_share(share).await {
        Ok(_) => {
            let _ = state.nix.generate_all().await;
        }
        Err(e) => {
            tracing::error!("Failed to create share: {}", e);
        }
    }
    HtmlTemplate(SmbRowTemplate { share: share_view })
}

async fn get_smb_edit_form(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let config = state.state_manager.get_smb().await;
    if let Some(share) = config.shares.into_iter().find(|s| s.id == id) {
        let share_view: SmbShareView = share.into();
        HtmlTemplate(SmbEditTemplate { share: share_view }).into_response()
    } else {
        (StatusCode::NOT_FOUND, "Share not found").into_response()
    }
}

async fn update_smb_share(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
    Form(form): Form<CreateShareForm>,
) -> impl IntoResponse {
    let valid_users = parse_user_list(&form.valid_users);
    let write_list = parse_user_list(&form.write_list);

    let mut share = SmbShare::new(form.name.clone(), form.path.clone());
    share.id = id;
    share.comment = form.comment.clone().unwrap_or_default();
    share.guest_ok = form.guest_ok.is_some();
    share.guest_only = form.guest_only.is_some();
    share.read_only = form.read_only.is_some();
    share.browseable = form.browseable.is_some();
    share.valid_users = valid_users;
    share.invalid_users = parse_user_list(&form.invalid_users);
    share.write_list = write_list;
    share.read_list = parse_user_list(&form.read_list);
    share.force_user = parse_optional_string(&form.force_user);
    share.force_group = parse_optional_string(&form.force_group);
    if let Some(ref mask) = form.create_mask
        && !mask.is_empty()
    {
        share.create_mask = mask.clone();
    }
    if let Some(ref mask) = form.directory_mask
        && !mask.is_empty()
    {
        share.directory_mask = mask.clone();
    }
    share.force_create_mode = parse_optional_string(&form.force_create_mode);
    share.force_directory_mode = parse_optional_string(&form.force_directory_mode);
    share.inherit_acls = form.inherit_acls.is_some();
    share.inherit_permissions = form.inherit_permissions.is_some();
    share.ea_support = form.ea_support.is_some();
    share.store_dos_attributes = form.store_dos_attributes.is_some();
    share.hide_dot_files = form.hide_dot_files.is_some();
    share.hide_special_files = form.hide_special_files.is_some();
    share.follow_symlinks = form.follow_symlinks.is_some();
    share.wide_links = form.wide_links.is_some();
    share.vfs_objects = parse_user_list(&form.vfs_objects);
    share.time_machine = form.time_machine.is_some();
    share.hosts_allow = parse_user_list(&form.hosts_allow);
    share.hosts_deny = parse_user_list(&form.hosts_deny);
    share.recycle_bin = form.recycle_bin.is_some();
    share.recycle_max_size = form
        .recycle_max_size
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    share.recycle_retention_days = form
        .recycle_retention_days
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    share.audit_enabled = form.audit_enabled.is_some();
    share.smb_encrypt = form
        .smb_encrypt
        .clone()
        .unwrap_or_else(|| "auto".to_string());
    share.extra_options = form.extra_options.clone().unwrap_or_default();

    if let Err(e) = create_share_directory(&share.path).await {
        tracing::warn!("Failed to setup share directory: {}", e);
    }

    let share_view: SmbShareView = share.clone().into();
    match state.smb.update_share(share).await {
        Ok(_) => {
            let _ = state.nix.generate_all().await;
        }
        Err(e) => {
            tracing::error!("Failed to update share: {}", e);
        }
    }
    HtmlTemplate(SmbRowTemplate { share: share_view })
}

async fn delete_smb_share(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.smb.delete_share(id).await {
        Ok(_) => {
            let _ = state.nix.generate_all().await;
            Html("").into_response()
        }
        Err(e) => {
            tracing::error!("Failed to delete share: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed").into_response()
        }
    }
}

use crate::commands::acl::{self, AclEntry, AclPermission, AclType, SetAclOptions};

/// ACL entry for display
#[derive(Clone)]
struct AclEntryDisplay {
    acl_type: String,
    acl_type_lower: String,
    name: String,
    permission: String,
    permission_label: String,
}

async fn get_share_acl(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;

    let share = match nas_state.smb.shares.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return Html("<p>Share not found</p>".to_string()).into_response(),
    };

    let path = &share.path;
    let share_name = &share.name;

    let acl_available = acl::is_available().await;

    let (acl_supported, owner, group, entries, default_entries) = if acl_available {
        match acl::get_acl(path).await {
            Ok(info) => {
                let entries: Vec<AclEntryDisplay> = info
                    .entries
                    .iter()
                    .map(|e| AclEntryDisplay {
                        acl_type: format!("{:?}", e.acl_type),
                        acl_type_lower: format!("{}", e.acl_type),
                        name: e.name.clone(),
                        permission: format!("{:?}", e.permission),
                        permission_label: e.permission.label().to_string(),
                    })
                    .collect();

                let default_entries: Vec<AclEntryDisplay> = info
                    .default_entries
                    .iter()
                    .map(|e| AclEntryDisplay {
                        acl_type: format!("{:?}", e.acl_type),
                        acl_type_lower: format!("{}", e.acl_type),
                        name: e.name.clone(),
                        permission: format!("{:?}", e.permission),
                        permission_label: e.permission.label().to_string(),
                    })
                    .collect();

                (true, info.owner, info.group, entries, default_entries)
            }
            Err(_) => (false, String::new(), String::new(), vec![], vec![]),
        }
    } else {
        (false, String::new(), String::new(), vec![], vec![])
    };

    let available_users: Vec<String> = nas_state
        .system_users
        .iter()
        .map(|u| u.username.clone())
        .collect();

    let available_groups: Vec<String> = nas_state
        .system_groups
        .iter()
        .map(|g| g.name.clone())
        .collect();

    let html = format!(
        r##"<div id="acl-content">
    <input type="hidden" id="acl-share-id" value="{}">
    <input type="hidden" id="acl-share-path" value="{}">

    <div style="margin-bottom: 1rem;">
        <strong>Share:</strong> {}<br>
        <strong>Path:</strong> <code>{}</code>
    </div>

    {}
</div>"##,
        id,
        path,
        share_name,
        path,
        if !acl_supported {
            r##"<article style="background: var(--pico-del-color); color: white; padding: 1rem;">
        <p>⚠️ This filesystem does not support POSIX ACLs or ACL tools are not available.</p>
        <p>ACLs are supported on ext4, XFS, and ZFS (with acltype=posixacl).</p>
    </article>"##
                .to_string()
        } else {
            format!(
                r##"
    <!-- Current Owner -->
    <div class="card" style="margin-bottom: 1rem; padding: 1rem;">
        <div class="grid" style="grid-template-columns: 1fr 1fr;">
            <div><strong>Owner:</strong> {}</div>
            <div><strong>Group:</strong> {}</div>
        </div>
    </div>

    <!-- Current ACL entries -->
    <div class="card" style="margin-bottom: 1rem;">
        <header style="padding: 0.75rem 1rem;">
            <h4 style="margin: 0;">Current Permissions</h4>
        </header>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Name</th>
                    <th>Permission</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="acl-entries">
                {}
            </tbody>
        </table>
    </div>

    {}

    <!-- Add new ACL entry -->
    <div class="card" style="margin-bottom: 1rem;">
        <header style="padding: 0.75rem 1rem;">
            <h4 style="margin: 0;">➕ Add Permission</h4>
        </header>
        <form hx-post="/api/web/smb/shares/{}/acl"
              hx-target="#acl-content"
              hx-swap="outerHTML"
              style="padding: 1rem;">
            <div class="grid" style="grid-template-columns: 1fr 2fr 2fr auto;">
                <label>
                    Type
                    <select name="acl_type" required>
                        <option value="user">User</option>
                        <option value="group">Group</option>
                    </select>
                </label>
                <label>
                    Name
                    <input type="text" name="name" required placeholder="username or groupname" list="nameslist">
                    <datalist id="nameslist">
                        {}
                    </datalist>
                </label>
                <label>
                    Permission
                    <select name="permission" required>
                        <option value="none">No access</option>
                        <option value="read">Read only</option>
                        <option value="readwrite" selected>Read/Write</option>
                        <option value="full">Full control</option>
                    </select>
                </label>
                <label>
                    &nbsp;
                    <button type="submit" style="margin: 0;">Add</button>
                </label>
            </div>
            <div class="grid" style="grid-template-columns: 1fr 1fr;">
                <label>
                    <input type="checkbox" name="recursive">
                    Apply recursively to all files and subdirectories
                </label>
                <label>
                    <input type="checkbox" name="set_default" checked>
                    Set as default (apply to new files)
                </label>
            </div>
        </form>
    </div>

    <!-- Bulk actions -->
    <div class="card">
        <header style="padding: 0.75rem 1rem;">
            <h4 style="margin: 0;">🔧 Bulk Actions</h4>
        </header>
        <div style="padding: 1rem; display: flex; gap: 1rem; flex-wrap: wrap;">
            <button class="secondary outline"
                    hx-delete="/api/web/smb/shares/{}/acl/all"
                    hx-target="#acl-content"
                    hx-swap="outerHTML"
                    hx-confirm="Remove all extended ACLs? This will reset to standard Unix permissions.">
                🗑️ Remove All Extended ACLs
            </button>
        </div>
    </div>"##,
                owner,
                group,
                if entries.is_empty() {
                    r#"<tr><td colspan="4" style="text-align: center; color: var(--pico-muted-color);">
                        No extended ACL entries. Using standard Unix permissions.
                    </td></tr>"#.to_string()
                } else {
                    entries
                        .iter()
                        .map(|e| {
                            let type_icon = match e.acl_type.as_str() {
                                "User" => "👤 User",
                                "Group" => "👥 Group",
                                "Mask" => "🎭 Mask",
                                _ => "🌐 Other",
                            };
                            let name_display = if e.name.is_empty() {
                                "<em>(owner)</em>".to_string()
                            } else {
                                e.name.clone()
                            };
                            let badge_class = match e.permission.as_str() {
                                "Full" | "ReadWrite" => "badge-success",
                                "Read" | "ReadExecute" => "badge-info",
                                _ => "badge-warning",
                            };
                            let delete_btn = if !e.name.is_empty() {
                                format!(
                                    r##"<button class="small outline secondary"
                                    hx-delete="/api/web/smb/shares/{}/acl/{}/{}"
                                    hx-target="#acl-content"
                                    hx-swap="outerHTML"
                                    hx-confirm="Remove ACL for {}?">
                                🗑️
                            </button>"##,
                                    id, e.acl_type_lower, e.name, e.name
                                )
                            } else {
                                String::new()
                            };
                            format!(
                                r#"<tr>
                            <td>{}</td>
                            <td>{}</td>
                            <td><span class="badge {}">{}</span></td>
                            <td>{}</td>
                        </tr>"#,
                                type_icon,
                                name_display,
                                badge_class,
                                e.permission_label,
                                delete_btn
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                if default_entries.is_empty() {
                    String::new()
                } else {
                    let rows = default_entries
                        .iter()
                        .map(|e| {
                            let type_icon = match e.acl_type.as_str() {
                                "User" => "👤 User",
                                "Group" => "👥 Group",
                                _ => "🌐 Other",
                            };
                            let name_display = if e.name.is_empty() {
                                "<em>(owner)</em>".to_string()
                            } else {
                                e.name.clone()
                            };
                            let badge_class = match e.permission.as_str() {
                                "Full" | "ReadWrite" => "badge-success",
                                "Read" | "ReadExecute" => "badge-info",
                                _ => "badge-warning",
                            };
                            format!(
                                r#"<tr>
                            <td>{}</td>
                            <td>{}</td>
                            <td><span class="badge {}">{}</span></td>
                        </tr>"#,
                                type_icon, name_display, badge_class, e.permission_label
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");

                    format!(
                        r#"<div class="card" style="margin-bottom: 1rem;">
        <header style="padding: 0.75rem 1rem;">
            <h4 style="margin: 0;">Default Permissions (for new files)</h4>
        </header>
        <table>
            <thead><tr><th>Type</th><th>Name</th><th>Permission</th></tr></thead>
            <tbody>{}</tbody>
        </table>
    </div>"#,
                        rows
                    )
                },
                id,
                {
                    let mut opts = String::new();
                    for u in &available_users {
                        opts.push_str(&format!(r#"<option value="{}">"#, u));
                    }
                    for g in &available_groups {
                        opts.push_str(&format!(r#"<option value="{}">"#, g));
                    }
                    opts
                },
                id
            )
        }
    );

    Html(html).into_response()
}

#[derive(Deserialize)]
struct AddAclForm {
    acl_type: String,
    name: String,
    permission: String,
    recursive: Option<String>,
    set_default: Option<String>,
}

async fn add_share_acl(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
    Form(form): Form<AddAclForm>,
) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;

    let share = match nas_state.smb.shares.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return Html("<p>Share not found</p>".to_string()).into_response(),
    };

    let path = &share.path;

    let acl_type = match form.acl_type.as_str() {
        "user" => AclType::User,
        "group" => AclType::Group,
        _ => return Html("<p>Invalid ACL type</p>".to_string()).into_response(),
    };

    let permission = match form.permission.as_str() {
        "none" => AclPermission::None,
        "read" => AclPermission::Read,
        "readwrite" => AclPermission::ReadWrite,
        "full" => AclPermission::Full,
        _ => AclPermission::ReadWrite,
    };

    let entry = AclEntry {
        acl_type,
        name: form.name.clone(),
        permission,
        is_default: false,
    };

    let options = SetAclOptions {
        recursive: form.recursive.is_some(),
        replace: false,
        set_default: form.set_default.is_some(),
    };

    if let Err(e) = acl::set_acl(path, &entry, &options).await {
        tracing::error!("Failed to set ACL: {}", e);
        return Html(format!(
            "<p style=\"color: var(--pico-del-color);\">Error: {}</p>",
            e
        ))
        .into_response();
    }

    tracing::info!("Added ACL entry for {} on share {}", form.name, share.name);

    drop(nas_state);
    get_share_acl(State(state), Path(id)).await.into_response()
}

async fn remove_share_acl(
    State(state): State<Arc<WebState>>,
    Path((id, acl_type, name)): Path<(Uuid, String, String)>,
) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;

    let share = match nas_state.smb.shares.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return Html("<p>Share not found</p>".to_string()).into_response(),
    };

    let path = &share.path;

    let acl_type_enum = match acl_type.as_str() {
        "user" | "u" => AclType::User,
        "group" | "g" => AclType::Group,
        _ => return Html("<p>Invalid ACL type</p>".to_string()).into_response(),
    };

    if let Err(e) = acl::remove_acl(path, &acl_type_enum, &name, false).await {
        tracing::error!("Failed to remove ACL: {}", e);
        return Html(format!(
            "<p style=\"color: var(--pico-del-color);\">Error: {}</p>",
            e
        ))
        .into_response();
    }

    tracing::info!("Removed ACL entry for {} on share {}", name, share.name);

    drop(nas_state);
    get_share_acl(State(state), Path(id)).await.into_response()
}

async fn remove_all_share_acl(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;

    let share = match nas_state.smb.shares.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return Html("<p>Share not found</p>".to_string()).into_response(),
    };

    let path = &share.path;

    if let Err(e) = acl::remove_all_acl(path, false).await {
        tracing::error!("Failed to remove all ACLs: {}", e);
        return Html(format!(
            "<p style=\"color: var(--pico-del-color);\">Error: {}</p>",
            e
        ))
        .into_response();
    }

    tracing::info!("Removed all extended ACLs on share {}", share.name);

    drop(nas_state);
    get_share_acl(State(state), Path(id)).await.into_response()
}

async fn get_share_privileges(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;

    let share = match nas_state.smb.shares.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return Html("<p>Share not found</p>".to_string()).into_response(),
    };

    let all_users: Vec<&str> = nas_state
        .system_users
        .iter()
        .map(|u| u.username.as_str())
        .collect();

    let all_groups: Vec<&str> = nas_state
        .system_groups
        .iter()
        .map(|g| g.name.as_str())
        .collect();

    let mut priv_rows = String::new();
    for priv_entry in &share.privileges {
        let icon = if priv_entry.is_group { "👥" } else { "👤" };
        let type_label = if priv_entry.is_group { "Group" } else { "User" };

        let (no_access_sel, read_sel, rw_sel) = match priv_entry.permission {
            PrivilegeLevel::NoAccess => ("selected", "", ""),
            PrivilegeLevel::ReadOnly => ("", "selected", ""),
            PrivilegeLevel::ReadWrite => ("", "", "selected"),
        };

        priv_rows.push_str(&format!(
            r##"<tr>
            <td>{} {}</td>
            <td><small style="color: var(--pico-muted-color);">{}</small></td>
            <td>
                <select name="perm_{type_label}_{name}" style="margin: 0; padding: 0.25rem;">
                    <option value="0" {no_access_sel}>❌ No access</option>
                    <option value="5" {read_sel}>👁️ Read only</option>
                    <option value="7" {rw_sel}>✏️ Read/Write</option>
                </select>
            </td>
            <td>
                <button type="button" class="small outline secondary"
                        hx-delete="/api/web/smb/shares/{share_id}/privileges/{type_label}/{name}"
                        hx-target="#privileges-content"
                        hx-swap="outerHTML">
                    🗑️
                </button>
            </td>
        </tr>"##,
            icon,
            priv_entry.name,
            type_label,
            type_label = type_label.to_lowercase(),
            name = priv_entry.name,
            no_access_sel = no_access_sel,
            read_sel = read_sel,
            rw_sel = rw_sel,
            share_id = id,
        ));
    }

    if share.privileges.is_empty() {
        priv_rows =
            r#"<tr><td colspan="4" style="text-align: center; color: var(--pico-muted-color);">
            No privileges configured. All authenticated users have access based on share settings.
        </td></tr>"#
                .to_string();
    }

    let mut user_options = String::new();
    for user in &all_users {
        if !share
            .privileges
            .iter()
            .any(|p| !p.is_group && p.name == *user)
        {
            user_options.push_str(&format!(
                r#"<option value="user:{}">👤 {}</option>"#,
                user, user
            ));
        }
    }
    for group in &all_groups {
        if !share
            .privileges
            .iter()
            .any(|p| p.is_group && p.name == *group)
        {
            user_options.push_str(&format!(
                r#"<option value="group:{}">👥 {}</option>"#,
                group, group
            ));
        }
    }

    let html = format!(
        r##"<div id="privileges-content">
    <div style="margin-bottom: 1rem;">
        <strong>Share:</strong> {share_name}<br>
        <strong>Path:</strong> <code>{path}</code>
    </div>

    <form hx-post="/api/web/smb/shares/{id}/privileges"
          hx-target="#privileges-content"
          hx-swap="outerHTML">

        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Permission</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                {priv_rows}
            </tbody>
        </table>

        <fieldset style="margin-top: 1rem;">
            <legend>➕ Add User/Group</legend>
            <div class="grid" style="grid-template-columns: 2fr 1fr auto;">
                <select name="new_entry">
                    <option value="">-- Select user or group --</option>
                    {user_options}
                </select>
                <select name="new_permission">
                    <option value="7">✏️ Read/Write</option>
                    <option value="5">👁️ Read only</option>
                    <option value="0">❌ No access</option>
                </select>
                <button type="submit" name="action" value="add">Add</button>
            </div>
        </fieldset>

        <footer style="margin-top: 1rem;">
            <button type="button" class="secondary" onclick="document.getElementById(&quot;privileges-modal&quot;).close()">Close</button>
            <button type="submit" name="action" value="save">💾 Save All</button>
        </footer>
    </form>

    <details style="margin-top: 1rem;">
        <summary style="color: var(--pico-muted-color);">ℹ️ About Privileges vs ACL</summary>
        <p style="font-size: 0.9rem; color: var(--pico-muted-color);">
            <strong>Privileges</strong> (this dialog) are simple SMB-level permissions stored in the configuration.
            They control who can access the share via Samba/Windows sharing.<br><br>
            <strong>ACL</strong> (🔐 button) are advanced POSIX filesystem permissions that apply to all access methods
            (SMB, NFS, local, SSH). Use ACL for fine-grained control or when you need permissions to work across protocols.
        </p>
    </details>
</div>"##,
        share_name = share.name,
        path = share.path,
        id = id,
        priv_rows = priv_rows,
        user_options = user_options,
    );

    Html(html).into_response()
}

#[derive(Deserialize)]
struct PrivilegesForm {
    new_entry: Option<String>,
    new_permission: Option<String>,
    action: Option<String>,
    #[serde(flatten)]
    permissions: std::collections::HashMap<String, String>,
}

async fn save_share_privileges(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
    Form(form): Form<PrivilegesForm>,
) -> impl IntoResponse {
    let action = form.action.as_deref().unwrap_or("save");

    let smb_config = state.state_manager.get_smb().await;

    let mut share = match smb_config.shares.iter().find(|s| s.id == id).cloned() {
        Some(s) => s,
        None => return Html("<p>Share not found</p>".to_string()).into_response(),
    };

    if action == "add"
        && let Some(ref new_entry) = form.new_entry
        && !new_entry.is_empty()
    {
        let parts: Vec<&str> = new_entry.splitn(2, ':').collect();
        if parts.len() == 2 {
            let is_group = parts[0] == "group";
            let name = parts[1].to_string();
            let permission = match form.new_permission.as_deref() {
                Some("0") => PrivilegeLevel::NoAccess,
                Some("5") => PrivilegeLevel::ReadOnly,
                _ => PrivilegeLevel::ReadWrite,
            };

            if !share
                .privileges
                .iter()
                .any(|p| p.name == name && p.is_group == is_group)
            {
                share.privileges.push(SharePrivilege {
                    name,
                    is_group,
                    permission,
                });
            }
        }
    }

    for (key, value) in &form.permissions {
        if key.starts_with("perm_") {
            let parts: Vec<&str> = key.trim_start_matches("perm_").splitn(2, '_').collect();
            if parts.len() == 2 {
                let is_group = parts[0] == "group";
                let name = parts[1];

                if let Some(priv_entry) = share
                    .privileges
                    .iter_mut()
                    .find(|p| p.name == name && p.is_group == is_group)
                {
                    priv_entry.permission = match value.as_str() {
                        "0" => PrivilegeLevel::NoAccess,
                        "5" => PrivilegeLevel::ReadOnly,
                        _ => PrivilegeLevel::ReadWrite,
                    };
                }
            }
        }
    }

    let share_name = share.name.clone();

    if let Err(e) = state.state_manager.update_smb_share(share).await {
        tracing::error!("Failed to save privileges: {}", e);
        return Html(format!(
            "<p style=\"color: var(--pico-del-color);\">Error: {}</p>",
            e
        ))
        .into_response();
    }

    let _ = state.nix.generate_all().await;

    tracing::info!("Updated privileges for share {}", share_name);

    get_share_privileges(State(state), Path(id))
        .await
        .into_response()
}

async fn delete_share_privilege(
    State(state): State<Arc<WebState>>,
    Path((id, priv_type, name)): Path<(Uuid, String, String)>,
) -> impl IntoResponse {
    let smb_config = state.state_manager.get_smb().await;

    let mut share = match smb_config.shares.iter().find(|s| s.id == id).cloned() {
        Some(s) => s,
        None => return Html("<p>Share not found</p>".to_string()).into_response(),
    };

    let is_group = priv_type == "group";

    share
        .privileges
        .retain(|p| !(p.name == name && p.is_group == is_group));

    let share_name = share.name.clone();

    if let Err(e) = state.state_manager.update_smb_share(share).await {
        tracing::error!("Failed to delete privilege: {}", e);
        return Html(format!(
            "<p style=\"color: var(--pico-del-color);\">Error: {}</p>",
            e
        ))
        .into_response();
    }

    let _ = state.nix.generate_all().await;

    tracing::info!("Deleted privilege for {} on share {}", name, share_name);

    get_share_privileges(State(state), Path(id))
        .await
        .into_response()
}

async fn toggle_smb(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let config = state.state_manager.get_smb().await;
    let _ = state.smb.set_enabled(!config.enabled).await;
    let _ = state.nix.generate_all().await;
    Html("")
}

async fn get_smb_global_settings(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let config = state.state_manager.get_smb().await;

    let protocol_options = vec![
        ("SMB2", "SMB2 (Windows Vista+)"),
        ("SMB2_02", "SMB2.02"),
        ("SMB2_10", "SMB2.1"),
        ("SMB3", "SMB3 (Windows 8+)"),
        ("SMB3_00", "SMB3.0"),
        ("SMB3_02", "SMB3.02"),
        ("SMB3_11", "SMB3.1.1 (most secure)"),
    ];

    let mut protocol_select = String::new();
    for (val, label) in &protocol_options {
        let selected = if config.min_protocol == *val {
            "selected"
        } else {
            ""
        };
        protocol_select.push_str(&format!(
            r#"<option value="{}" {}>{}</option>"#,
            val, selected, label
        ));
    }

    let log_levels: Vec<(&str, &str)> = vec![
        ("0", "None"),
        ("1", "1"),
        ("2", "2"),
        ("3", "3"),
        ("4", "4"),
        ("5", "5"),
        ("6", "6"),
        ("7", "7"),
        ("8", "8"),
        ("9", "9"),
        ("10", "10 (Debug)"),
    ];
    let mut log_select = String::new();
    for (val, label) in &log_levels {
        let selected = if config.log_level.to_string() == *val {
            "selected"
        } else {
            ""
        };
        log_select.push_str(&format!(
            r#"<option value="{}" {}>{}</option>"#,
            val, selected, label
        ));
    }

    Html(format!(
        r##"
<form hx-post="/api/web/smb/global-settings" hx-target="#smb-settings-container" hx-swap="innerHTML" style="max-height: 70vh; overflow-y: auto;">
    <fieldset>
        <legend>🌐 Network</legend>
        <div class="grid">
            <label>
                Workgroup
                <input type="text" name="workgroup" value="{workgroup}">
            </label>
            <label>
                Server Description
                <input type="text" name="server_string" value="{server_string}">
            </label>
        </div>
        <div class="grid">
            <label>
                <input type="checkbox" name="disable_netbios" {disable_netbios_checked}>
                Disable NetBIOS
            </label>
            <label>
                <input type="checkbox" name="wins_support" {wins_support_checked}>
                Enable WINS Server
            </label>
        </div>
        <label>
            WINS Server Address
            <input type="text" name="wins_server" value="{wins_server}" placeholder="192.168.1.1">
            <small>External WINS server to use</small>
        </label>
        <label>
            <input type="checkbox" name="time_server" {time_server_checked}>
            Act as Time Server
            <small>Provide time to Windows clients</small>
        </label>
    </fieldset>

    <fieldset>
        <legend>🔒 Protocol</legend>
        <label>
            Minimum Protocol Version
            <select name="min_protocol">
                {protocol_select}
            </select>
        </label>
    </fieldset>

    <fieldset>
        <legend>⚡ Performance</legend>
        <div class="grid">
            <label>
                <input type="checkbox" name="use_sendfile" {use_sendfile_checked}>
                Use Sendfile
            </label>
            <label>
                <input type="checkbox" name="aio_enabled" {aio_enabled_checked}>
                Async I/O (AIO)
            </label>
        </div>
        <label>
            <input type="checkbox" name="unix_extensions" {unix_extensions_checked}>
            Unix Extensions
        </label>
    </fieldset>

    <fieldset>
        <legend>🍎 Apple</legend>
        <label>
            <input type="checkbox" name="time_machine_support" {time_machine_checked}>
            Enable Time Machine Support
        </label>
    </fieldset>

    <fieldset>
        <legend>👤 Guest</legend>
        <label>
            Guest Account
            <input type="text" name="guest_account" value="{guest_account}">
        </label>
    </fieldset>

    <fieldset>
        <legend>📝 Default Permissions</legend>
        <div class="grid">
            <label>
                Create Mask
                <input type="text" name="global_create_mask" value="{global_create_mask}">
            </label>
            <label>
                Directory Mask
                <input type="text" name="global_directory_mask" value="{global_directory_mask}">
            </label>
        </div>
    </fieldset>

    <fieldset>
        <legend>📊 Logging</legend>
        <label>
            Log Level
            <select name="log_level">
                {log_select}
            </select>
        </label>
    </fieldset>

    <details>
        <summary>🏠 Home Directories</summary>
        <fieldset>
            <label>
                <input type="checkbox" name="homes_enabled" {homes_enabled_checked}>
                Enable Home Directories Share
            </label>
            <label>
                <input type="checkbox" name="homes_browseable" {homes_browseable_checked}>
                Browseable
            </label>
            <div class="grid">
                <label>
                    <input type="checkbox" name="homes_inherit_acls" {homes_inherit_acls_checked}>
                    Inherit ACLs
                </label>
                <label>
                    <input type="checkbox" name="homes_inherit_permissions" {homes_inherit_permissions_checked}>
                    Inherit Permissions
                </label>
            </div>
            <label>
                <input type="checkbox" name="homes_recycle_bin" {homes_recycle_bin_checked}>
                Enable Recycle Bin
            </label>
            <div class="grid">
                <label>
                    <input type="checkbox" name="homes_follow_symlinks" {homes_follow_symlinks_checked}>
                    Follow Symlinks
                </label>
                <label>
                    <input type="checkbox" name="homes_wide_links" {homes_wide_links_checked}>
                    Wide Links
                </label>
            </div>
            <label>
                Extra Options
                <textarea name="homes_extra_options" rows="2" placeholder="key = value">{homes_extra_options}</textarea>
            </label>
        </fieldset>
    </details>

    <details>
        <summary>📄 Extra Options</summary>
        <fieldset>
            <label>
                Raw smb.conf global options (one per line: key = value)
                <textarea name="extra_options" rows="3" placeholder="socket options = TCP_NODELAY">{extra_options}</textarea>
            </label>
        </fieldset>
    </details>

    <footer>
        <button type="button" class="secondary" onclick="document.getElementById('settings-modal').close()">Cancel</button>
        <button type="submit">💾 Save Settings</button>
    </footer>
</form>
"##,
        workgroup = config.workgroup,
        server_string = config.server_string,
        disable_netbios_checked = if config.disable_netbios {
            "checked"
        } else {
            ""
        },
        wins_support_checked = if config.wins_support { "checked" } else { "" },
        wins_server = config.wins_server,
        time_server_checked = if config.time_server { "checked" } else { "" },
        protocol_select = protocol_select,
        use_sendfile_checked = if config.use_sendfile { "checked" } else { "" },
        aio_enabled_checked = if config.aio_enabled { "checked" } else { "" },
        unix_extensions_checked = if config.unix_extensions {
            "checked"
        } else {
            ""
        },
        time_machine_checked = if config.time_machine_support {
            "checked"
        } else {
            ""
        },
        guest_account = config.guest_account,
        global_create_mask = config.global_create_mask,
        global_directory_mask = config.global_directory_mask,
        log_select = log_select,
        homes_enabled_checked = if config.homes_enabled { "checked" } else { "" },
        homes_browseable_checked = if config.homes_browseable {
            "checked"
        } else {
            ""
        },
        homes_inherit_acls_checked = if config.homes_inherit_acls {
            "checked"
        } else {
            ""
        },
        homes_inherit_permissions_checked = if config.homes_inherit_permissions {
            "checked"
        } else {
            ""
        },
        homes_recycle_bin_checked = if config.homes_recycle_bin {
            "checked"
        } else {
            ""
        },
        homes_follow_symlinks_checked = if config.homes_follow_symlinks {
            "checked"
        } else {
            ""
        },
        homes_wide_links_checked = if config.homes_wide_links {
            "checked"
        } else {
            ""
        },
        homes_extra_options = config.homes_extra_options,
        extra_options = config.extra_options,
    ))
}

#[derive(Deserialize)]
struct SmbGlobalSettingsForm {
    workgroup: String,
    server_string: String,
    #[serde(default)]
    disable_netbios: Option<String>,
    #[serde(default)]
    wins_support: Option<String>,
    #[serde(default)]
    wins_server: Option<String>,
    min_protocol: String,
    #[serde(default)]
    use_sendfile: Option<String>,
    #[serde(default)]
    aio_enabled: Option<String>,
    #[serde(default)]
    unix_extensions: Option<String>,
    #[serde(default)]
    time_machine_support: Option<String>,
    #[serde(default)]
    time_server: Option<String>,
    guest_account: String,
    global_create_mask: String,
    global_directory_mask: String,
    #[serde(default)]
    log_level: Option<String>,
    #[serde(default)]
    extra_options: Option<String>,
    #[serde(default)]
    homes_enabled: Option<String>,
    #[serde(default)]
    homes_browseable: Option<String>,
    #[serde(default)]
    homes_inherit_acls: Option<String>,
    #[serde(default)]
    homes_inherit_permissions: Option<String>,
    #[serde(default)]
    homes_recycle_bin: Option<String>,
    #[serde(default)]
    homes_follow_symlinks: Option<String>,
    #[serde(default)]
    homes_wide_links: Option<String>,
    #[serde(default)]
    homes_extra_options: Option<String>,
}

async fn update_smb_global_settings(
    State(state): State<Arc<WebState>>,
    Form(form): Form<SmbGlobalSettingsForm>,
) -> impl IntoResponse {
    let _ = state
        .state_manager
        .update(|s| {
            s.smb.workgroup = form.workgroup.clone();
            s.smb.server_string = form.server_string.clone();
            s.smb.disable_netbios = form.disable_netbios.is_some();
            s.smb.wins_support = form.wins_support.is_some();
            s.smb.wins_server = form.wins_server.clone().unwrap_or_default();
            s.smb.min_protocol = form.min_protocol.clone();
            s.smb.use_sendfile = form.use_sendfile.is_some();
            s.smb.aio_enabled = form.aio_enabled.is_some();
            s.smb.unix_extensions = form.unix_extensions.is_some();
            s.smb.time_machine_support = form.time_machine_support.is_some();
            s.smb.time_server = form.time_server.is_some();
            s.smb.guest_account = form.guest_account.clone();
            s.smb.global_create_mask = form.global_create_mask.clone();
            s.smb.global_directory_mask = form.global_directory_mask.clone();
            s.smb.log_level = form
                .log_level
                .as_ref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            s.smb.extra_options = form.extra_options.clone().unwrap_or_default();
            s.smb.homes_enabled = form.homes_enabled.is_some();
            s.smb.homes_browseable = form.homes_browseable.is_some();
            s.smb.homes_inherit_acls = form.homes_inherit_acls.is_some();
            s.smb.homes_inherit_permissions = form.homes_inherit_permissions.is_some();
            s.smb.homes_recycle_bin = form.homes_recycle_bin.is_some();
            s.smb.homes_follow_symlinks = form.homes_follow_symlinks.is_some();
            s.smb.homes_wide_links = form.homes_wide_links.is_some();
            s.smb.homes_extra_options = form.homes_extra_options.clone().unwrap_or_default();
            s.pending_changes = true;
        })
        .await;

    let _ = state.nix.generate_all().await;

    Html(
        r#"<div class="feedback-success" style="padding: 1rem; border-radius: 0.5rem; text-align: center;">✅ Settings saved. Apply changes to activate.</div>"#,
    )
}

async fn list_samba_users(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let users = state.state_manager.get_samba_users().await;
    let mut html = String::new();

    if users.is_empty() {
        html.push_str(r##"<tr><td colspan="5" style="text-align: center; color: var(--pico-muted-color);">No users configured. Click "New User" to create one.</td></tr>"##);
    } else {
        for user in &users {
            let status_badge = if user.enabled {
                r##"<span class="badge badge-success">Enabled</span>"##
            } else {
                r##"<span class="badge badge-warning">Disabled</span>"##
            };
            let toggle_class = if user.enabled { "" } else { "secondary" };
            let toggle_icon = if user.enabled { "⏸️" } else { "▶️" };

            html.push_str(&format!(
                r##"<tr id="samba-user-{id}">
                    <td><code>{username}</code></td>
                    <td>{description}</td>
                    <td>{groups}</td>
                    <td>{status}</td>
                    <td>
                        <div class="btn-group">
                            <button class="small outline" onclick="openSetPasswordModal('{id}', '{username}')">🔑</button>
                            <button class="small outline {toggle_class}" hx-post="/api/web/smb/users/{id}/toggle" hx-target="#samba-user-{id}" hx-swap="outerHTML">{toggle_icon}</button>
                            <button class="small outline secondary" hx-delete="/api/web/smb/users/{id}" hx-target="#samba-user-{id}" hx-swap="outerHTML" hx-confirm="Delete user {username}?">🗑️</button>
                        </div>
                    </td>
                </tr>"##,
                id = user.id,
                username = user.username,
                description = user.description,
                groups = user.groups.join(", "),
                status = status_badge,
                toggle_class = toggle_class,
                toggle_icon = toggle_icon,
            ));
        }
    }

    Html(html)
}

#[derive(Deserialize)]
struct CreateSambaUserForm {
    username: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    groups: String,
    password: String,
}

async fn create_samba_user(
    State(state): State<Arc<WebState>>,
    Form(form): Form<CreateSambaUserForm>,
) -> impl IntoResponse {
    let groups: Vec<String> = form
        .groups
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let user = SambaUser {
        id: Uuid::new_v4(),
        username: form.username.clone(),
        password_set: false,
        description: form.description,
        enabled: true,
        groups,
    };

    let user_id = user.id;

    match state.state_manager.add_samba_user(user).await {
        Ok(_) => {
            let _ = state.nix.apply().await;

            if let Err(e) = samba::set_password(&form.username, &form.password).await {
                return HtmlTemplate(BuildOutputTemplate {
                    success: false,
                    title: "User Created but Password Failed".to_string(),
                    output: "System user created. Please set password manually.".to_string(),
                    error: e.to_string(),
                });
            }

            let _ = state
                .state_manager
                .set_samba_user_password_set(user_id, true)
                .await;

            HtmlTemplate(BuildOutputTemplate {
                success: true,
                title: "User Created".to_string(),
                output: format!("Samba user '{}' created successfully", form.username),
                error: String::new(),
            })
        }
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Create User Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn delete_samba_user(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.state_manager.delete_samba_user(id).await {
        Ok(username) => {
            let _ = samba::delete_user(&username).await;
            let _ = state.nix.generate_all().await;
            Html("").into_response()
        }
        Err(e) => {
            tracing::error!("Failed to delete user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed").into_response()
        }
    }
}

#[derive(Deserialize)]
struct SetPasswordForm {
    password: String,
}

async fn set_samba_user_password(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
    Form(form): Form<SetPasswordForm>,
) -> impl IntoResponse {
    let users = state.state_manager.get_samba_users().await;
    let user = match users.iter().find(|u| u.id == id) {
        Some(u) => u,
        None => {
            return HtmlTemplate(BuildOutputTemplate {
                success: false,
                title: "Set Password Failed".to_string(),
                output: String::new(),
                error: "User not found".to_string(),
            });
        }
    };

    match samba::set_password(&user.username, &form.password).await {
        Ok(_) => {
            let _ = state
                .state_manager
                .set_samba_user_password_set(id, true)
                .await;
            HtmlTemplate(BuildOutputTemplate {
                success: true,
                title: "Password Updated".to_string(),
                output: format!("Password for '{}' updated successfully", user.username),
                error: String::new(),
            })
        }
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Set Password Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn toggle_samba_user(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let users = state.state_manager.get_samba_users().await;
    let user = match users.iter().find(|u| u.id == id) {
        Some(u) => u.clone(),
        None => return Html("<tr><td colspan=\"5\">User not found</td></tr>".to_string()),
    };

    let new_enabled = !user.enabled;
    let mut updated_user = user.clone();
    updated_user.enabled = new_enabled;

    if let Err(e) = state
        .state_manager
        .update_samba_user(updated_user.clone())
        .await
    {
        tracing::error!("Failed to toggle user: {}", e);
        return Html("<tr><td colspan=\"5\">Failed to toggle user</td></tr>".to_string());
    }

    if new_enabled {
        let _ = samba::enable_user(&user.username).await;
    } else {
        let _ = samba::disable_user(&user.username).await;
    }

    let status_badge = if updated_user.enabled {
        r##"<span class="badge badge-success">Enabled</span>"##
    } else {
        r##"<span class="badge badge-warning">Disabled</span>"##
    };
    let toggle_class = if updated_user.enabled {
        ""
    } else {
        "secondary"
    };
    let toggle_icon = if updated_user.enabled {
        "⏸️"
    } else {
        "▶️"
    };

    Html(format!(
        r##"<tr id="samba-user-{id}">
            <td><code>{username}</code></td>
            <td>{description}</td>
            <td>{groups}</td>
            <td>{status}</td>
            <td>
                <div class="btn-group">
                    <button class="small outline" onclick="openSetPasswordModal('{id}', '{username}')">🔑</button>
                    <button class="small outline {toggle_class}" hx-post="/api/web/smb/users/{id}/toggle" hx-target="#samba-user-{id}" hx-swap="outerHTML">{toggle_icon}</button>
                    <button class="small outline secondary" hx-delete="/api/web/smb/users/{id}" hx-target="#samba-user-{id}" hx-swap="outerHTML" hx-confirm="Delete user {username}?">🗑️</button>
                </div>
            </td>
        </tr>"##,
        id = updated_user.id,
        username = updated_user.username,
        description = updated_user.description,
        groups = updated_user.groups.join(", "),
        status = status_badge,
        toggle_class = toggle_class,
        toggle_icon = toggle_icon,
    ))
}

#[derive(Deserialize)]
struct CreateExportForm {
    path: String,
    client_host: String,
    #[serde(default)]
    permission: Option<String>, // "rw" or "ro"
    #[serde(default)]
    sync: Option<String>,
    #[serde(default)]
    no_root_squash: Option<String>,
    #[serde(default)]
    subtree_check: Option<String>,
    #[serde(default)]
    insecure: Option<String>,
    #[serde(default)]
    extra_options: Option<String>,
}

async fn create_nfs_export(
    State(state): State<Arc<WebState>>,
    Form(form): Form<CreateExportForm>,
) -> impl IntoResponse {
    let mut opts = vec![];

    if form.permission.as_deref() == Some("ro") {
        opts.push("ro".to_string());
    } else {
        opts.push("rw".to_string());
    }

    if form.sync.is_some() {
        opts.push("sync".to_string());
    } else {
        opts.push("async".to_string());
    }

    if form.no_root_squash.is_some() {
        opts.push("no_root_squash".to_string());
    } else {
        opts.push("root_squash".to_string());
    }

    if form.subtree_check.is_some() {
        opts.push("subtree_check".to_string());
    } else {
        opts.push("no_subtree_check".to_string());
    }

    if form.insecure.is_some() {
        opts.push("insecure".to_string());
    }

    if let Err(e) = create_share_directory(&form.path).await {
        tracing::warn!("Failed to setup export directory: {}", e);
    }

    let export = NfsExport {
        id: Uuid::new_v4(),
        path: form.path,
        clients: vec![NfsClient {
            host: form.client_host,
            options: opts,
        }],
        extra_options: form.extra_options.unwrap_or_default(),
    };
    let export_view: NfsExportView = export.clone().into();
    match state.nfs.create_export(export).await {
        Ok(_) => {
            let _ = state.nix.generate_all().await;
        }
        Err(e) => {
            tracing::error!("Failed to create export: {}", e);
        }
    }
    HtmlTemplate(NfsRowTemplate {
        export: export_view,
    })
}

async fn delete_nfs_export(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.nfs.delete_export(id).await {
        Ok(_) => {
            let _ = state.nix.generate_all().await;
            Html("").into_response()
        }
        Err(e) => {
            tracing::error!("Failed to delete export: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed").into_response()
        }
    }
}

async fn toggle_nfs(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let config = state.state_manager.get_nfs().await;
    let _ = state.nfs.set_enabled(!config.enabled).await;
    let _ = state.nix.generate_all().await;
    Html("")
}

async fn get_nfs_settings(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let config = state.state_manager.get_nfs().await;

    let versions = vec!["3", "4", "4.1", "4.2"];
    let mut version_checkboxes = String::new();
    for v in &versions {
        let checked = if config.versions.contains(&v.to_string()) {
            "checked"
        } else {
            ""
        };
        version_checkboxes.push_str(&format!(
            r#"<label><input type="checkbox" name="versions" value="{}" {}> NFSv{}</label>"#,
            v, checked, v
        ));
    }

    Html(format!(
        r##"
<form hx-post="/api/web/nfs/settings" hx-target="#nfs-settings-container" hx-swap="innerHTML">
    <fieldset>
        <legend>📋 NFS Versions</legend>
        <div class="grid">
            {version_checkboxes}
        </div>
        <small>Select which NFS protocol versions to enable</small>
    </fieldset>

    <fieldset>
        <legend>⚡ Performance</legend>
        <label>
            Server Threads
            <input type="number" name="threads" value="{threads}" min="1" max="64">
            <small>Number of NFS server threads (default: 8)</small>
        </label>
    </fieldset>

    <footer>
        <button type="button" class="secondary" onclick="document.getElementById('nfs-settings-modal').close()">Cancel</button>
        <button type="submit">💾 Save Settings</button>
    </footer>
</form>
"##,
        version_checkboxes = version_checkboxes,
        threads = config.threads,
    ))
}

#[derive(Deserialize)]
struct NfsSettingsForm {
    #[serde(default)]
    versions: Vec<String>,
    threads: u32,
}

async fn update_nfs_settings(
    State(state): State<Arc<WebState>>,
    Form(form): Form<NfsSettingsForm>,
) -> impl IntoResponse {
    let _ = state
        .state_manager
        .update(|s| {
            s.nfs.versions = if form.versions.is_empty() {
                vec!["3".to_string(), "4".to_string()]
            } else {
                form.versions.clone()
            };
            s.nfs.threads = form.threads;
            s.pending_changes = true;
        })
        .await;

    let _ = state.nix.generate_all().await;

    Html(
        r#"<div class="feedback-success" style="padding: 1rem; border-radius: 0.5rem; text-align: center;">✅ NFS settings saved.</div>"#,
    )
}

async fn dry_build(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    match state.nix.dry_build().await {
        Ok(result) => HtmlTemplate(BuildOutputTemplate {
            success: result.success,
            title: "Dry Build".to_string(),
            output: result.output,
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Dry Build Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn apply_config(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    if let Err(e) = state.nix.generate_all().await {
        return HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Generation Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        });
    }
    match state.nix.apply().await {
        Ok(result) => {
            if result.success {
                let _ = state.state_manager.clear_pending().await;

                let pending_passwords = {
                    let mut passwords = Vec::new();
                    let _ = state
                        .state_manager
                        .update(|s| {
                            passwords = std::mem::take(&mut s.pending_samba_passwords);
                        })
                        .await;
                    passwords
                };

                for (username, password) in pending_passwords {
                    let _ = crate::commands::samba::set_password(&username, &password).await;
                }
            }
            HtmlTemplate(BuildOutputTemplate {
                success: result.success,
                title: if result.success {
                    "Configuration Applied".to_string()
                } else {
                    "Apply Failed".to_string()
                },
                output: result.output,
                error: String::new(),
            })
        }
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Apply Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn rollback(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    match state.nix.rollback().await {
        Ok(result) => HtmlTemplate(BuildOutputTemplate {
            success: result.success,
            title: "Rollback".to_string(),
            output: result.output,
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Rollback Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn upgrade_system(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    match state.nix.upgrade().await {
        Ok(result) => HtmlTemplate(BuildOutputTemplate {
            success: result.success,
            title: "System Upgrade".to_string(),
            output: format!(
                "{}\n\n⚠️ Reboot required to apply the upgrade.",
                result.output
            ),
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Upgrade Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn switch_generation(
    State(state): State<Arc<WebState>>,
    Path(generation): Path<u32>,
) -> impl IntoResponse {
    match state.nix.switch_generation(generation).await {
        Ok(result) => HtmlTemplate(BuildOutputTemplate {
            success: result.success,
            title: format!("Switched to Generation {}", generation),
            output: result.output,
            error: String::new(),
        }),
        Err(e) => HtmlTemplate(BuildOutputTemplate {
            success: false,
            title: "Switch Failed".to_string(),
            output: String::new(),
            error: e.to_string(),
        }),
    }
}

async fn get_config_file(Path(file): Path<String>) -> impl IntoResponse {
    let path = format!("/etc/nixos/nas/{}", file);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => Html(content).into_response(),
        Err(_) => Html("File not found".to_string()).into_response(),
    }
}

async fn get_pending_status(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let pending = state.state_manager.has_pending_changes().await;
    if pending {
        Html(
            r#"<div id="pending-banner" class="pending-banner" hx-swap-oob="true">
            <span>⚠️ Configuration changes pending</span>
            <a href="/system" class="btn-apply">Apply Now</a>
        </div>"#
                .to_string(),
        )
    } else {
        Html(r#"<div id="pending-banner" hx-swap-oob="true"></div>"#.to_string())
    }
}

async fn list_backups(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let backups = state.state_manager.list_backups().await;

    if backups.is_empty() {
        return Html(r#"<p style="color: var(--pico-muted-color);">No backups available yet. Backups are created automatically when configuration changes.</p>"#.to_string());
    }

    let mut html = String::from(
        r#"<table><thead><tr><th>Backup</th><th>Date</th><th>Action</th></tr></thead><tbody>"#,
    );

    for backup in backups {
        let filename = backup
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Extract timestamp from filename (state.json.YYYYMMDD_HHMMSS)
        let date_str = filename
            .strip_prefix("state.json.")
            .and_then(|s| {
                if s.len() >= 15 {
                    let year = &s[0..4];
                    let month = &s[4..6];
                    let day = &s[6..8];
                    let hour = &s[9..11];
                    let min = &s[11..13];
                    let sec = &s[13..15];
                    Some(format!(
                        "{}-{}-{} {}:{}:{}",
                        year, month, day, hour, min, sec
                    ))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| filename.clone());

        html.push_str(&format!(
            r##"<tr>
                <td><code>{}</code></td>
                <td>{}</td>
                <td>
                    <button class="small outline"
                            hx-post="/api/web/system/backups/restore/{}"
                            hx-target="#backup-result"
                            hx-confirm="Restore this backup? Current configuration will be backed up first.">
                        🔄 Restore
                    </button>
                </td>
            </tr>"##,
            filename, date_str, filename
        ));
    }

    html.push_str("</tbody></table>");
    html.push_str(r##"<div id="backup-result"></div>"##);

    Html(html)
}

async fn restore_backup(
    State(state): State<Arc<WebState>>,
    Path(filename): Path<String>,
) -> impl IntoResponse {
    if filename.contains('/') || filename.contains("..") {
        return Html(
            r#"<p style="color: var(--pico-del-color);">Invalid filename</p>"#.to_string(),
        );
    }

    let backup_path = std::path::PathBuf::from("/var/lib/nixnas").join(&filename);

    match state.state_manager.restore_backup(&backup_path).await {
        Ok(_) => {
            let _ = state.nix.generate_all().await;
            Html(format!(
                r#"<p style="color: var(--pico-ins-color);">✅ Successfully restored from {}</p>"#,
                filename
            ))
        }
        Err(e) => Html(format!(
            r#"<p style="color: var(--pico-del-color);">❌ Failed to restore: {}</p>"#,
            e
        )),
    }
}

/// Hash a password using SHA-512 format compatible with NixOS hashedPassword
async fn hash_password(password: &str) -> Option<String> {
    // Try mkpasswd first (NixOS standard)
    let result = tokio::process::Command::new("mkpasswd")
        .arg("-m")
        .arg("sha-512")
        .arg(password)
        .output()
        .await;

    if let Ok(output) = result
        && output.status.success()
    {
        let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if hash.starts_with("$6$") {
            return Some(hash);
        }
    }

    // Fallback: try openssl
    let result = tokio::process::Command::new("openssl")
        .arg("passwd")
        .arg("-6")
        .arg(password)
        .output()
        .await;

    if let Ok(output) = result
        && output.status.success()
    {
        let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if hash.starts_with("$6$") {
            return Some(hash);
        }
    }

    None
}

async fn list_system_users(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    let users = &nas_state.system_users;

    if users.is_empty() {
        return Html(r##"<tr><td colspan="7" style="text-align: center; color: var(--pico-muted-color);">No users configured. Click "New User" to create one.</td></tr>"##.to_string());
    }

    let mut html = String::new();
    for user in users {
        let status = if user.enabled {
            r#"<span class="badge badge-success">Enabled</span>"#
        } else {
            r#"<span class="badge badge-warning">Disabled</span>"#
        };
        let samba_status = if user.samba_access {
            r#"<span class="badge badge-success">Yes</span>"#
        } else {
            r#"<span class="badge badge-secondary">No</span>"#
        };
        let groups = user.groups.join(", ");
        let shell_short = user.shell.split('/').next_back().unwrap_or(&user.shell);

        html.push_str(&format!(r##"
        <tr id="user-{id}">
            <td><code>{username}</code></td>
            <td>{description}</td>
            <td>{groups}</td>
            <td><code>{shell}</code></td>
            <td>{samba}</td>
            <td>{status}</td>
            <td>
                <div class="btn-group">
                    <button class="btn-icon" title="Edit"
                            hx-get="/api/web/users/{id}"
                            hx-target="#edit-user-container"
                            hx-on::after-request="document.getElementById('edit-user-modal').showModal()">✏️</button>
                    <button class="btn-icon" title="Set Password"
                            onclick="openSetUserPasswordModal('{id}', '{username}')">🔑</button>
                    <button class="btn-icon btn-danger" title="Delete"
                            hx-delete="/api/web/users/{id}"
                            hx-target="#user-{id}"
                            hx-swap="outerHTML"
                            hx-confirm="Delete user {username}?">🗑️</button>
                </div>
            </td>
        </tr>
        "##,
            id = user.id,
            username = user.username,
            description = user.description,
            groups = groups,
            shell = shell_short,
            samba = samba_status,
            status = status,
        ));
    }
    Html(html)
}

#[derive(Deserialize)]
struct CreateSystemUserForm {
    username: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    email: Option<String>,
    password: String,
    #[serde(default)]
    #[allow(dead_code)]
    password_confirm: Option<String>,
    #[serde(default)]
    shell: Option<String>,
    #[serde(default)]
    uid: Option<String>, // String to handle empty field
    #[serde(default)]
    groups: Option<String>,
    #[serde(default)]
    ssh_keys: Option<String>,
    #[serde(default)]
    home_dir: Option<String>,
    #[serde(default)]
    create_home: Option<String>,
}

async fn create_system_user(
    State(state): State<Arc<WebState>>,
    Form(form): Form<CreateSystemUserForm>,
) -> impl IntoResponse {
    let groups: Vec<String> = form
        .groups
        .as_ref()
        .map(|g| {
            g.split([',', ' '])
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let ssh_keys: Vec<String> = form
        .ssh_keys
        .as_ref()
        .map(|k| {
            k.lines()
                .filter(|l| !l.trim().is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let shell = form
        .shell
        .clone()
        .unwrap_or_else(|| "/usr/bin/nologin".to_string());
    let ssh_access = !shell.contains("nologin");

    let hashed_password = hash_password(&form.password).await;

    let uid: Option<u32> = form.uid.as_ref().and_then(|s| s.trim().parse().ok());

    let mut user = SystemUser::new(form.username.clone());
    user.description = form.description.unwrap_or_default();
    user.email = form.email.unwrap_or_default();
    user.uid = uid; // Set UID if provided
    user.shell = shell;
    user.groups = groups;
    user.ssh_keys = ssh_keys;
    user.home_dir = form.home_dir.filter(|s| !s.trim().is_empty());
    user.create_home = form.create_home.is_some();
    user.enabled = true;
    user.samba_access = true; // All users have Samba access
    user.hashed_password = hashed_password;
    user.is_system_user = !ssh_access; // System user if no login shell

    let username = form.username.clone();
    let password = form.password.clone();

    let _ = state
        .state_manager
        .update(|s| {
            s.system_users.push(user);
            s.pending_changes = true;
            s.pending_samba_passwords
                .push((username.clone(), password.clone()));
        })
        .await;

    let _ = state.nix.generate_all().await;

    list_system_users(State(state)).await
}

async fn get_system_user(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    if let Some(user) = nas_state.system_users.iter().find(|u| u.id == id) {
        let shells = vec![
            ("/bin/bash", "Bash"),
            ("/bin/sh", "Sh"),
            ("/bin/zsh", "Zsh"),
            ("/usr/bin/nologin", "No Login"),
        ];
        let mut shell_options = String::new();
        for (val, label) in &shells {
            let selected = if user.shell == *val { "selected" } else { "" };
            shell_options.push_str(&format!(
                r#"<option value="{}" {}>{}</option>"#,
                val, selected, label
            ));
        }

        Html(format!(
            r##"
<form hx-put="/api/web/users/{id}"
      hx-target="#users-list"
      hx-swap="innerHTML"
      hx-on::after-request="if(event.detail.successful) {{ document.getElementById('edit-user-modal').close(); showToast('User updated'); }}">
    <label>
        Username
        <input type="text" name="username" value="{username}" readonly>
    </label>
    <label>
        Description
        <input type="text" name="description" value="{description}">
    </label>
    <label>
        Email
        <input type="email" name="email" value="{email}">
    </label>
    <label>
        Shell
        <select name="shell">{shell_options}</select>
    </label>
    <label>
        Groups
        <input type="text" name="groups" value="{groups}">
    </label>
    <details>
        <summary>SSH Keys</summary>
        <textarea name="ssh_keys" rows="3">{ssh_keys}</textarea>
    </details>
    <footer>
        <button type="button" class="secondary" onclick="document.getElementById('edit-user-modal').close()">Cancel</button>
        <button type="submit">Save Changes</button>
    </footer>
</form>
"##,
            id = user.id,
            username = user.username,
            description = user.description,
            email = user.email,
            shell_options = shell_options,
            groups = user.groups.join(" "),
            ssh_keys = user.ssh_keys.join("\n"),
        ))
    } else {
        Html("<p>User not found</p>".to_string())
    }
}

#[derive(Deserialize)]
struct UpdateSystemUserForm {
    #[allow(dead_code)]
    username: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    shell: Option<String>,
    #[serde(default)]
    groups: Option<String>,
    #[serde(default)]
    ssh_keys: Option<String>,
}

async fn update_system_user(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
    Form(form): Form<UpdateSystemUserForm>,
) -> impl IntoResponse {
    let groups: Vec<String> = form
        .groups
        .as_ref()
        .map(|g| {
            g.split([',', ' '])
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let ssh_keys: Vec<String> = form
        .ssh_keys
        .as_ref()
        .map(|k| {
            k.lines()
                .filter(|l| !l.trim().is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let _ = state
        .state_manager
        .update(|s| {
            if let Some(user) = s.system_users.iter_mut().find(|u| u.id == id) {
                user.description = form.description.clone().unwrap_or_default();
                user.email = form.email.clone().unwrap_or_default();
                user.shell = form
                    .shell
                    .clone()
                    .unwrap_or_else(|| "/bin/bash".to_string());
                user.groups = groups.clone();
                user.ssh_keys = ssh_keys.clone();
            }
            s.pending_changes = true;
        })
        .await;

    let _ = state.nix.generate_all().await;

    list_system_users(State(state)).await
}

async fn delete_system_user(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let _ = state
        .state_manager
        .update(|s| {
            s.system_users.retain(|u| u.id != id);
            s.pending_changes = true;
        })
        .await;

    let _ = state.nix.generate_all().await;

    Html("")
}

#[derive(Deserialize)]
struct SetUserPasswordForm {
    password: String,
}

async fn set_system_user_password(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
    Form(form): Form<SetUserPasswordForm>,
) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    if let Some(user) = nas_state.system_users.iter().find(|u| u.id == id) {
        let _ = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "echo '{}:{}' | sudo chpasswd",
                user.username, form.password
            ))
            .output()
            .await;
        Html(r#"<div class="success">✅ Password updated</div>"#)
    } else {
        Html(r#"<div class="error">❌ User not found</div>"#)
    }
}

async fn get_home_settings(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    let config = &nas_state.home_directories;

    Html(format!(
        r##"
<form hx-post="/api/web/users/home-settings" hx-target="#home-settings-container" hx-swap="innerHTML">
    <label>
        <input type="checkbox" name="enabled" {enabled_checked}>
        Enable Home Directories
    </label>
    <label>
        Base Path
        <input type="text" name="base_path" value="{base_path}" placeholder="/home">
        <small>Root directory for user home folders</small>
    </label>
    <footer>
        <button type="button" class="secondary" onclick="document.getElementById('settings-modal').close()">Cancel</button>
        <button type="submit">💾 Save</button>
    </footer>
</form>
"##,
        enabled_checked = if config.enabled { "checked" } else { "" },
        base_path = config.base_path,
    ))
}

#[derive(Deserialize)]
struct HomeSettingsForm {
    #[serde(default)]
    enabled: Option<String>,
    base_path: String,
}

async fn update_home_settings(
    State(state): State<Arc<WebState>>,
    Form(form): Form<HomeSettingsForm>,
) -> impl IntoResponse {
    let _ = state
        .state_manager
        .update(|s| {
            s.home_directories.enabled = form.enabled.is_some();
            s.home_directories.base_path = form.base_path.clone();
            s.pending_changes = true;
        })
        .await;

    let _ = state.nix.generate_all().await;

    Html(
        r#"<div class="feedback-success" style="padding: 1rem; border-radius: 0.5rem; text-align: center;">✅ Settings saved</div>"#,
    )
}

async fn list_system_groups(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    let groups = &nas_state.system_groups;

    if groups.is_empty() {
        return Html(r##"<tr><td colspan="4" style="text-align: center; color: var(--pico-muted-color);">No groups configured. Click "New Group" to create one.</td></tr>"##.to_string());
    }

    let mut html = String::new();
    for group in groups {
        let members = group.members.join(", ");

        html.push_str(&format!(
            r##"
        <tr id="group-{id}">
            <td><code>{name}</code></td>
            <td>{description}</td>
            <td>{members}</td>
            <td>
                <button class="btn-icon btn-danger" title="Delete"
                        hx-delete="/api/web/groups/{id}"
                        hx-target="#group-{id}"
                        hx-swap="outerHTML"
                        hx-confirm="Delete group {name}?">🗑️</button>
            </td>
        </tr>
        "##,
            id = group.id,
            name = group.name,
            description = if group.description.is_empty() {
                "-".to_string()
            } else {
                group.description.clone()
            },
            members = if members.is_empty() {
                "-".to_string()
            } else {
                members
            },
        ));
    }
    Html(html)
}

#[derive(Deserialize)]
struct CreateGroupForm {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    members: Option<String>,
}

async fn create_system_group(
    State(state): State<Arc<WebState>>,
    Form(form): Form<CreateGroupForm>,
) -> impl IntoResponse {
    let members: Vec<String> = form
        .members
        .as_ref()
        .map(|m| m.split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let mut group = SystemGroup::new(form.name);
    group.description = form.description.unwrap_or_default();
    group.members = members;

    let _ = state
        .state_manager
        .update(|s| {
            s.system_groups.push(group);
            s.pending_changes = true;
        })
        .await;

    let _ = state.nix.generate_all().await;

    list_system_groups(State(state)).await
}

async fn delete_system_group(
    State(state): State<Arc<WebState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let _ = state
        .state_manager
        .update(|s| {
            s.system_groups.retain(|g| g.id != id);
            s.pending_changes = true;
        })
        .await;

    let _ = state.nix.generate_all().await;

    Html("")
}

async fn toggle_ssh(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let _ = state
        .state_manager
        .update(|s| {
            s.settings.ssh_enabled = !s.settings.ssh_enabled;
            s.pending_changes = true;
        })
        .await;
    let _ = state.nix.generate_all().await;
    Html("")
}

#[derive(Deserialize)]
struct SshSettingsForm {
    port: u16,
    #[serde(default)]
    permit_root_login: Option<String>,
    #[serde(default)]
    password_auth: Option<String>,
    #[serde(default)]
    pubkey_auth: Option<String>,
}

async fn update_ssh_settings(
    State(state): State<Arc<WebState>>,
    Form(form): Form<SshSettingsForm>,
) -> impl IntoResponse {
    let _ = state
        .state_manager
        .update(|s| {
            s.settings.ssh_port = form.port;
            s.settings.ssh_permit_root_login = form.permit_root_login.is_some();
            s.settings.ssh_password_auth = form.password_auth.is_some();
            s.settings.ssh_pubkey_auth = form.pubkey_auth.is_some();
            s.pending_changes = true;
        })
        .await;
    let _ = state.nix.generate_all().await;
    Html("")
}

async fn toggle_rsync(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let _ = state
        .state_manager
        .update(|s| {
            s.settings.rsync_enabled = !s.settings.rsync_enabled;
            s.pending_changes = true;
        })
        .await;
    let _ = state.nix.generate_all().await;
    Html("")
}

#[derive(Deserialize)]
struct CreateRsyncModuleForm {
    name: String,
    path: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    uid: Option<String>,
    #[serde(default)]
    gid: Option<String>,
    #[serde(default)]
    use_chroot: Option<String>,
    #[serde(default)]
    auth_users: Option<String>,
    #[serde(default)]
    read_only: Option<String>,
    #[serde(default)]
    write_only: Option<String>,
    #[serde(default)]
    list: Option<String>,
    #[serde(default)]
    max_connections: Option<u32>,
    #[serde(default)]
    hosts_allow: Option<String>,
    #[serde(default)]
    hosts_deny: Option<String>,
    #[serde(default)]
    extra_options: Option<String>,
}

async fn list_rsync_modules(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let nas_state = state.state_manager.get().await;
    let modules = &nas_state.rsync_modules;

    if modules.is_empty() {
        return Html(r##"<tr><td colspan="5" style="text-align: center; color: var(--pico-muted-color);">No modules configured. Click "New Module" to create one.</td></tr>"##.to_string());
    }

    let mut html = String::new();
    for module in modules {
        let access = if module.read_only && module.write_only {
            "R/W"
        } else if module.read_only {
            "Read Only"
        } else if module.write_only {
            "Write Only"
        } else {
            "Full Access"
        };

        html.push_str(&format!(
            r##"
        <tr id="rsync-module-{name}">
            <td><code>{name}</code></td>
            <td><code>{path}</code></td>
            <td>{uid}:{gid}</td>
            <td>{access}</td>
            <td>
                <button class="btn-icon btn-danger" title="Delete"
                        hx-delete="/api/web/rsync/modules/{name}"
                        hx-target="#rsync-module-{name}"
                        hx-swap="outerHTML"
                        hx-confirm="Delete module {name}?">🗑️</button>
            </td>
        </tr>
        "##,
            name = module.name,
            path = module.path,
            uid = module.uid,
            gid = module.gid,
            access = access,
        ));
    }
    Html(html)
}

async fn create_rsync_module(
    State(state): State<Arc<WebState>>,
    Form(form): Form<CreateRsyncModuleForm>,
) -> impl IntoResponse {
    let module = RsyncModule {
        name: form.name,
        path: form.path,
        comment: form.comment.unwrap_or_default(),
        uid: form
            .uid
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "nobody".to_string()),
        gid: form
            .gid
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "nogroup".to_string()),
        use_chroot: form.use_chroot.is_some(),
        auth_users: form.auth_users.is_some(),
        read_only: form.read_only.is_some(),
        write_only: form.write_only.is_some(),
        list: form.list.is_some(),
        max_connections: form.max_connections.unwrap_or(0),
        hosts_allow: form.hosts_allow.unwrap_or_default(),
        hosts_deny: form.hosts_deny.unwrap_or_default(),
        extra_options: form.extra_options.unwrap_or_default(),
    };

    let _ = state
        .state_manager
        .update(|s| {
            s.rsync_modules.push(module);
            s.pending_changes = true;
        })
        .await;
    let _ = state.nix.generate_all().await;

    list_rsync_modules(State(state)).await
}

async fn delete_rsync_module(
    State(state): State<Arc<WebState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let _ = state
        .state_manager
        .update(|s| {
            s.rsync_modules.retain(|m| m.name != name);
            s.pending_changes = true;
        })
        .await;
    let _ = state.nix.generate_all().await;
    Html("")
}
