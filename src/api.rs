use crate::auth::AuthManager;
use crate::commands::{btrfs, filesystem, mdadm, smart, zfs};
use crate::error::{RpcError, RpcResult};
use crate::nix::NixGenerator;
use crate::services::{nfs::NfsService, smb::SmbService};
use crate::state::{NfsExport, SmbShare, StateManager};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State, WebSocketUpgrade},
    http::StatusCode,
    response::Response,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

/// Shared application state.
pub struct AppState {
    pub state_manager: Arc<StateManager>,
    pub auth: Arc<AuthManager>,
    pub smb: Arc<SmbService>,
    pub nfs: Arc<NfsService>,
    pub nix: Arc<NixGenerator>,
}

impl AppState {
    pub async fn new(state_path: &str, nix_output_dir: &str) -> RpcResult<Self> {
        let state_manager = Arc::new(
            StateManager::load(state_path)
                .await
                .map_err(|e| RpcError::Internal(e.to_string()))?,
        );

        Ok(Self {
            auth: Arc::new(AuthManager::new(state_manager.clone())),
            smb: Arc::new(SmbService::new(state_manager.clone())),
            nfs: Arc::new(NfsService::new(state_manager.clone())),
            nix: Arc::new(NixGenerator::new(state_manager.clone(), nix_output_dir)),
            state_manager,
        })
    }
}

/// Build the application router.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/rpc", post(rpc_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/api/auth/status", get(auth_status_handler))
        .route("/api/ws", get(websocket_handler))
        .route("/health", get(health_handler))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// RPC request format.
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub service: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// RPC response format.
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RpcResponse {
    pub fn ok(data: impl Serialize) -> Self {
        Self {
            success: true,
            data: Some(serde_json::to_value(data).unwrap_or(Value::Null)),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

async fn health_handler() -> &'static str {
    "OK"
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Debug, Serialize)]
struct LoginErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    locked_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempts_remaining: Option<usize>,
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<LoginErrorResponse>)> {
    let client_ip = addr.ip();

    if let Err(remaining_secs) = state.auth.check_rate_limit(client_ip).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(LoginErrorResponse {
                error: format!(
                    "Too many failed attempts. Try again in {} seconds.",
                    remaining_secs
                ),
                locked_seconds: Some(remaining_secs),
                attempts_remaining: None,
            }),
        ));
    }

    match state
        .auth
        .login(&req.username, &req.password, Some(client_ip))
        .await
    {
        Ok(token) => Ok(Json(LoginResponse { token })),
        Err(_e) => {
            let attempts = state.auth.rate_limiter().get_attempt_count(client_ip).await;
            let remaining = 5_usize.saturating_sub(attempts);

            Err((
                StatusCode::UNAUTHORIZED,
                Json(LoginErrorResponse {
                    error: if remaining > 0 {
                        format!("Invalid credentials. {} attempts remaining.", remaining)
                    } else {
                        "Invalid credentials.".to_string()
                    },
                    locked_seconds: None,
                    attempts_remaining: if remaining > 0 { Some(remaining) } else { None },
                }),
            ))
        }
    }
}

async fn auth_status_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let needs_setup = state.auth.needs_setup().await;
    Json(serde_json::json!({
        "needs_setup": needs_setup
    }))
}

async fn websocket_handler(ws: WebSocketUpgrade, State(_state): State<Arc<AppState>>) -> Response {
    ws.on_upgrade(|_socket| async {
        // WebSocket handling for long operations
        // TODO: Implement progress streaming
    })
}

async fn rpc_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RpcRequest>,
) -> (StatusCode, Json<RpcResponse>) {
    tracing::debug!(service = %req.service, method = %req.method, "RPC request");

    match dispatch_rpc(&state, &req).await {
        Ok(data) => (StatusCode::OK, Json(RpcResponse::ok(data))),
        Err(e) => {
            let status = match &e {
                RpcError::ServiceNotFound(_) | RpcError::MethodNotFound(_) => StatusCode::NOT_FOUND,
                RpcError::InvalidParams(_) => StatusCode::BAD_REQUEST,
                RpcError::Unauthorized => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(RpcResponse::err(e.to_string())))
        }
    }
}

async fn dispatch_rpc(state: &AppState, req: &RpcRequest) -> RpcResult<Value> {
    let service = req.service.to_lowercase();
    let method = req.method.as_str();
    let params = &req.params;

    match service.as_str() {
        "storage" => dispatch_storage(method, params).await,
        "zfs" => dispatch_zfs(method, params).await,
        "btrfs" => dispatch_btrfs(method, params).await,
        "mdadm" => dispatch_mdadm(method, params).await,
        "smart" => dispatch_smart(method, params).await,
        "smb" => dispatch_smb(state, method, params).await,
        "nfs" => dispatch_nfs(state, method, params).await,
        "system" => dispatch_system(state, method, params).await,
        _ => Err(RpcError::ServiceNotFound(req.service.clone())),
    }
}

async fn dispatch_storage(method: &str, params: &Value) -> RpcResult<Value> {
    match method {
        "list_disks" => {
            let disks = filesystem::list_disks().await?;
            Ok(serde_json::to_value(disks).unwrap())
        }
        "list_block_devices" => {
            let devices = filesystem::list_block_devices().await?;
            Ok(serde_json::to_value(devices).unwrap())
        }
        "get_device" => {
            let path: String = extract_param(params, "path")?;
            let device = filesystem::get_device(&path).await?;
            Ok(serde_json::to_value(device).unwrap())
        }
        "list_mounts" => {
            let mounts = filesystem::list_mounts().await?;
            Ok(serde_json::to_value(mounts).unwrap())
        }
        "is_mounted" => {
            let path: String = extract_param(params, "path")?;
            let mounted = filesystem::is_mounted(&path).await?;
            Ok(Value::Bool(mounted))
        }
        "mount" => {
            let device: String = extract_param(params, "device")?;
            let target: String = extract_param(params, "target")?;
            let fstype: Option<String> = extract_param_opt(params, "fstype");
            filesystem::mount(&device, &target, fstype.as_deref()).await?;
            Ok(Value::Bool(true))
        }
        "umount" => {
            let target: String = extract_param(params, "target")?;
            filesystem::umount(&target).await?;
            Ok(Value::Bool(true))
        }
        "umount_lazy" => {
            let target: String = extract_param(params, "target")?;
            filesystem::umount_lazy(&target).await?;
            Ok(Value::Bool(true))
        }
        "mkfs" => {
            let device: String = extract_param(params, "device")?;
            let fstype: String = extract_param(params, "fstype")?;
            let label: Option<String> = extract_param_opt(params, "label");
            let fs = match fstype.as_str() {
                "ext4" => filesystem::FsType::Ext4,
                "xfs" => filesystem::FsType::Xfs,
                "btrfs" => filesystem::FsType::Btrfs,
                "vfat" => filesystem::FsType::Vfat,
                "ntfs" => filesystem::FsType::Ntfs,
                _ => {
                    return Err(RpcError::InvalidParams(format!(
                        "Unknown fstype: {}",
                        fstype
                    )));
                }
            };
            filesystem::mkfs(&device, fs, label.as_deref()).await?;
            Ok(Value::Bool(true))
        }
        "resize" => {
            let device: String = extract_param(params, "device")?;
            let fstype: String = extract_param(params, "fstype")?;
            filesystem::resize_fs(&device, &fstype).await?;
            Ok(Value::Bool(true))
        }
        "wipe" => {
            let device: String = extract_param(params, "device")?;
            filesystem::wipe_device(&device).await?;
            Ok(Value::Bool(true))
        }
        "zap" => {
            let device: String = extract_param(params, "device")?;
            filesystem::zap_disk(&device).await?;
            Ok(Value::Bool(true))
        }
        "get_usage" => {
            let usage = filesystem::get_usage().await?;
            Ok(serde_json::to_value(usage).unwrap())
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn dispatch_zfs(method: &str, params: &Value) -> RpcResult<Value> {
    if !zfs::is_available().await {
        return Err(RpcError::Internal("ZFS is not available".to_string()));
    }

    match method {
        "list_pools" => {
            let pools = zfs::list_pools().await?;
            Ok(serde_json::to_value(pools).unwrap())
        }
        "get_pool" => {
            let name: String = extract_param(params, "name")?;
            let pool = zfs::get_pool(&name).await?;
            Ok(serde_json::to_value(pool).unwrap())
        }
        "pool_status" => {
            let name: String = extract_param(params, "name")?;
            let status = zfs::pool_status(&name).await?;
            Ok(serde_json::to_value(status).unwrap())
        }
        "create_pool" => {
            let name: String = extract_param(params, "name")?;
            let devices: Vec<String> = extract_param(params, "devices")?;
            let level: String = extract_param(params, "level")?;
            let raid = match level.as_str() {
                "stripe" => zfs::RaidLevel::Stripe,
                "mirror" => zfs::RaidLevel::Mirror,
                "raidz1" => zfs::RaidLevel::RaidZ1,
                "raidz2" => zfs::RaidLevel::RaidZ2,
                "raidz3" => zfs::RaidLevel::RaidZ3,
                _ => return Err(RpcError::InvalidParams(format!("Unknown level: {}", level))),
            };
            let dev_refs: Vec<&str> = devices.iter().map(|s| s.as_str()).collect();
            let options = zfs::CreatePoolOptions::nas_defaults();
            zfs::create_pool(&name, raid, &dev_refs, options).await?;
            Ok(Value::Bool(true))
        }
        "destroy_pool" => {
            let name: String = extract_param(params, "name")?;
            let force: bool = extract_param_opt(params, "force").unwrap_or(false);
            zfs::destroy_pool(&name, force).await?;
            Ok(Value::Bool(true))
        }
        "import_pool" => {
            let name: String = extract_param(params, "name")?;
            let force: bool = extract_param_opt(params, "force").unwrap_or(false);
            zfs::import_pool(&name, force).await?;
            Ok(Value::Bool(true))
        }
        "export_pool" => {
            let name: String = extract_param(params, "name")?;
            zfs::export_pool(&name).await?;
            Ok(Value::Bool(true))
        }
        "list_importable" => {
            let pools = zfs::list_importable().await?;
            Ok(serde_json::to_value(pools).unwrap())
        }
        "scrub_start" => {
            let name: String = extract_param(params, "name")?;
            zfs::scrub_start(&name).await?;
            Ok(Value::Bool(true))
        }
        "scrub_stop" => {
            let name: String = extract_param(params, "name")?;
            zfs::scrub_stop(&name).await?;
            Ok(Value::Bool(true))
        }
        "list_datasets" => {
            let datasets = zfs::list_datasets().await?;
            Ok(serde_json::to_value(datasets).unwrap())
        }
        "get_dataset" => {
            let name: String = extract_param(params, "name")?;
            let dataset = zfs::get_dataset(&name).await?;
            Ok(serde_json::to_value(dataset).unwrap())
        }
        "create_dataset" => {
            let name: String = extract_param(params, "name")?;
            let mountpoint: Option<String> = extract_param_opt(params, "mountpoint");
            zfs::create_dataset(&name, mountpoint.as_deref()).await?;
            Ok(Value::Bool(true))
        }
        "destroy_dataset" => {
            let name: String = extract_param(params, "name")?;
            let recursive: bool = extract_param_opt(params, "recursive").unwrap_or(false);
            zfs::destroy_dataset(&name, recursive).await?;
            Ok(Value::Bool(true))
        }
        "set_property" => {
            let name: String = extract_param(params, "name")?;
            let property: String = extract_param(params, "property")?;
            let value: String = extract_param(params, "value")?;
            zfs::set_property(&name, &property, &value).await?;
            Ok(Value::Bool(true))
        }
        "get_property" => {
            let name: String = extract_param(params, "name")?;
            let property: String = extract_param(params, "property")?;
            let value = zfs::get_property(&name, &property).await?;
            Ok(Value::String(value))
        }
        "list_snapshots" => {
            let snapshots = zfs::list_snapshots().await?;
            Ok(serde_json::to_value(snapshots).unwrap())
        }
        "create_snapshot" => {
            let dataset: String = extract_param(params, "dataset")?;
            let name: String = extract_param(params, "name")?;
            zfs::create_snapshot(&dataset, &name).await?;
            Ok(Value::Bool(true))
        }
        "destroy_snapshot" => {
            let name: String = extract_param(params, "name")?;
            zfs::destroy_snapshot(&name).await?;
            Ok(Value::Bool(true))
        }
        "rollback" => {
            let name: String = extract_param(params, "name")?;
            let force: bool = extract_param_opt(params, "force").unwrap_or(false);
            zfs::rollback(&name, force).await?;
            Ok(Value::Bool(true))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn dispatch_btrfs(method: &str, params: &Value) -> RpcResult<Value> {
    if !btrfs::is_available().await {
        return Err(RpcError::Internal("Btrfs tools not available".to_string()));
    }

    match method {
        "list_filesystems" => {
            let fs = btrfs::list_filesystems().await?;
            Ok(serde_json::to_value(fs).unwrap())
        }
        "create" => {
            let devices: Vec<String> = extract_param(params, "devices")?;
            let label: Option<String> = extract_param_opt(params, "label");
            let data: String =
                extract_param_opt(params, "data").unwrap_or_else(|| "single".to_string());
            let metadata: String =
                extract_param_opt(params, "metadata").unwrap_or_else(|| "dup".to_string());

            let data_profile = parse_btrfs_profile(&data)?;
            let meta_profile = parse_btrfs_profile(&metadata)?;
            let dev_refs: Vec<&str> = devices.iter().map(|s| s.as_str()).collect();

            btrfs::create(&dev_refs, label.as_deref(), data_profile, meta_profile).await?;
            Ok(Value::Bool(true))
        }
        "list_subvolumes" => {
            let path: String = extract_param(params, "path")?;
            let subvols = btrfs::list_subvolumes(&path).await?;
            Ok(serde_json::to_value(subvols).unwrap())
        }
        "create_subvolume" => {
            let path: String = extract_param(params, "path")?;
            btrfs::create_subvolume(&path).await?;
            Ok(Value::Bool(true))
        }
        "delete_subvolume" => {
            let path: String = extract_param(params, "path")?;
            btrfs::delete_subvolume(&path).await?;
            Ok(Value::Bool(true))
        }
        "create_snapshot" => {
            let source: String = extract_param(params, "source")?;
            let dest: String = extract_param(params, "dest")?;
            let readonly: bool = extract_param_opt(params, "readonly").unwrap_or(false);
            btrfs::create_snapshot(&source, &dest, readonly).await?;
            Ok(Value::Bool(true))
        }
        "subvolume_show" => {
            let path: String = extract_param(params, "path")?;
            let info = btrfs::subvolume_show(&path).await?;
            Ok(Value::String(info))
        }
        "device_add" => {
            let device: String = extract_param(params, "device")?;
            let mountpoint: String = extract_param(params, "mountpoint")?;
            btrfs::device_add(&device, &mountpoint).await?;
            Ok(Value::Bool(true))
        }
        "device_remove" => {
            let device: String = extract_param(params, "device")?;
            let mountpoint: String = extract_param(params, "mountpoint")?;
            btrfs::device_remove(&device, &mountpoint).await?;
            Ok(Value::Bool(true))
        }
        "device_stats" => {
            let path: String = extract_param(params, "path")?;
            let stats = btrfs::device_stats(&path).await?;
            Ok(Value::String(stats))
        }
        "scrub_start" => {
            let path: String = extract_param(params, "path")?;
            btrfs::scrub_start(&path).await?;
            Ok(Value::Bool(true))
        }
        "scrub_status" => {
            let path: String = extract_param(params, "path")?;
            let status = btrfs::scrub_status(&path).await?;
            Ok(Value::String(status))
        }
        "scrub_cancel" => {
            let path: String = extract_param(params, "path")?;
            btrfs::scrub_cancel(&path).await?;
            Ok(Value::Bool(true))
        }
        "balance_start" => {
            let path: String = extract_param(params, "path")?;
            btrfs::balance_start(&path).await?;
            Ok(Value::Bool(true))
        }
        "balance_status" => {
            let path: String = extract_param(params, "path")?;
            let status = btrfs::balance_status(&path).await?;
            Ok(Value::String(status))
        }
        "balance_cancel" => {
            let path: String = extract_param(params, "path")?;
            btrfs::balance_cancel(&path).await?;
            Ok(Value::Bool(true))
        }
        "filesystem_usage" => {
            let path: String = extract_param(params, "path")?;
            let usage = btrfs::filesystem_usage(&path).await?;
            Ok(Value::String(usage))
        }
        "defragment" => {
            let path: String = extract_param(params, "path")?;
            let recursive: bool = extract_param_opt(params, "recursive").unwrap_or(false);
            btrfs::defragment(&path, recursive).await?;
            Ok(Value::Bool(true))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

fn parse_btrfs_profile(s: &str) -> RpcResult<btrfs::BtrfsProfile> {
    match s.to_lowercase().as_str() {
        "single" => Ok(btrfs::BtrfsProfile::Single),
        "dup" => Ok(btrfs::BtrfsProfile::Dup),
        "raid0" => Ok(btrfs::BtrfsProfile::Raid0),
        "raid1" => Ok(btrfs::BtrfsProfile::Raid1),
        "raid1c3" => Ok(btrfs::BtrfsProfile::Raid1c3),
        "raid1c4" => Ok(btrfs::BtrfsProfile::Raid1c4),
        "raid5" => Ok(btrfs::BtrfsProfile::Raid5),
        "raid6" => Ok(btrfs::BtrfsProfile::Raid6),
        "raid10" => Ok(btrfs::BtrfsProfile::Raid10),
        _ => Err(RpcError::InvalidParams(format!(
            "Unknown btrfs profile: {}",
            s
        ))),
    }
}

async fn dispatch_mdadm(method: &str, params: &Value) -> RpcResult<Value> {
    if !mdadm::is_available().await {
        return Err(RpcError::Internal("mdadm not available".to_string()));
    }

    match method {
        "list_arrays" => {
            let arrays = mdadm::list_arrays().await?;
            Ok(serde_json::to_value(arrays).unwrap())
        }
        "array_detail" => {
            let device: String = extract_param(params, "device")?;
            let detail = mdadm::get_array_detail(&device).await?;
            Ok(serde_json::to_value(detail).unwrap())
        }
        "create_array" => {
            let device: String = extract_param(params, "device")?;
            let devices: Vec<String> = extract_param(params, "devices")?;
            let level: String = extract_param(params, "level")?;
            let spares: Vec<String> = extract_param_opt(params, "spares").unwrap_or_default();
            let raid = match level.as_str() {
                "0" | "raid0" => mdadm::RaidLevel::Raid0,
                "1" | "raid1" => mdadm::RaidLevel::Raid1,
                "4" | "raid4" => mdadm::RaidLevel::Raid4,
                "5" | "raid5" => mdadm::RaidLevel::Raid5,
                "6" | "raid6" => mdadm::RaidLevel::Raid6,
                "10" | "raid10" => mdadm::RaidLevel::Raid10,
                _ => return Err(RpcError::InvalidParams(format!("Unknown level: {}", level))),
            };
            let dev_refs: Vec<&str> = devices.iter().map(|s| s.as_str()).collect();
            let spare_refs: Vec<&str> = spares.iter().map(|s| s.as_str()).collect();
            mdadm::create_array(&device, raid, &dev_refs, &spare_refs).await?;
            Ok(Value::Bool(true))
        }
        "stop_array" => {
            let device: String = extract_param(params, "device")?;
            mdadm::stop_array(&device).await?;
            Ok(Value::Bool(true))
        }
        "assemble_array" => {
            let device: String = extract_param(params, "device")?;
            let devices: Vec<String> = extract_param(params, "devices")?;
            let dev_refs: Vec<&str> = devices.iter().map(|s| s.as_str()).collect();
            mdadm::assemble_array(&device, &dev_refs).await?;
            Ok(Value::Bool(true))
        }
        "assemble_scan" => {
            mdadm::assemble_scan().await?;
            Ok(Value::Bool(true))
        }
        "add_device" => {
            let array: String = extract_param(params, "array")?;
            let device: String = extract_param(params, "device")?;
            mdadm::add_device(&array, &device).await?;
            Ok(Value::Bool(true))
        }
        "remove_device" => {
            let array: String = extract_param(params, "array")?;
            let device: String = extract_param(params, "device")?;
            mdadm::remove_device(&array, &device).await?;
            Ok(Value::Bool(true))
        }
        "fail_device" => {
            let array: String = extract_param(params, "array")?;
            let device: String = extract_param(params, "device")?;
            mdadm::fail_device(&array, &device).await?;
            Ok(Value::Bool(true))
        }
        "replace_device" => {
            let array: String = extract_param(params, "array")?;
            let old_device: String = extract_param(params, "old_device")?;
            let new_device: String = extract_param(params, "new_device")?;
            mdadm::replace_device(&array, &old_device, &new_device).await?;
            Ok(Value::Bool(true))
        }
        "scan_config" => {
            let config = mdadm::scan_config().await?;
            Ok(Value::String(config))
        }
        "examine" => {
            let device: String = extract_param(params, "device")?;
            let info = mdadm::examine(&device).await?;
            Ok(Value::String(info))
        }
        "zero_superblock" => {
            let device: String = extract_param(params, "device")?;
            mdadm::zero_superblock(&device).await?;
            Ok(Value::Bool(true))
        }
        "grow_array" => {
            let device: String = extract_param(params, "device")?;
            let raid_devices: Option<u32> = extract_param_opt(params, "raid_devices");
            let level: Option<String> = extract_param_opt(params, "level");
            let level_enum = level.as_ref().map(|l| match l.as_str() {
                "0" | "raid0" => mdadm::RaidLevel::Raid0,
                "1" | "raid1" => mdadm::RaidLevel::Raid1,
                "5" | "raid5" => mdadm::RaidLevel::Raid5,
                "6" | "raid6" => mdadm::RaidLevel::Raid6,
                _ => mdadm::RaidLevel::Raid5,
            });
            mdadm::grow_array(&device, raid_devices, level_enum).await?;
            Ok(Value::Bool(true))
        }
        "get_sync_status" => {
            let device: String = extract_param(params, "device")?;
            let status = mdadm::get_sync_status(&device).await?;
            Ok(serde_json::to_value(status).unwrap())
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn dispatch_smart(method: &str, params: &Value) -> RpcResult<Value> {
    if !smart::is_available().await {
        return Err(RpcError::Internal("smartctl not available".to_string()));
    }

    match method {
        "get_info" => {
            let device: String = extract_param(params, "device")?;
            let info = smart::get_info(&device).await?;
            Ok(serde_json::to_value(info).unwrap())
        }
        "health_check" => {
            let device: String = extract_param(params, "device")?;
            let passed = smart::health_check(&device).await?;
            Ok(Value::Bool(passed))
        }
        "start_test" => {
            let device: String = extract_param(params, "device")?;
            let test_type: String = extract_param(params, "type")?;
            let tt = match test_type.as_str() {
                "short" => smart::TestType::Short,
                "long" => smart::TestType::Long,
                "conveyance" => smart::TestType::Conveyance,
                _ => {
                    return Err(RpcError::InvalidParams(format!(
                        "Unknown test type: {}",
                        test_type
                    )));
                }
            };
            smart::start_test(&device, tt).await?;
            Ok(Value::Bool(true))
        }
        "get_test_results" => {
            let device: String = extract_param(params, "device")?;
            let results = smart::get_test_results(&device).await?;
            Ok(serde_json::to_value(results).unwrap())
        }
        "abort_test" => {
            let device: String = extract_param(params, "device")?;
            smart::abort_test(&device).await?;
            Ok(Value::Bool(true))
        }
        "get_power_mode" => {
            let device: String = extract_param(params, "device")?;
            let mode = smart::get_power_mode(&device).await?;
            Ok(Value::String(mode))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn dispatch_smb(state: &AppState, method: &str, params: &Value) -> RpcResult<Value> {
    match method {
        "get_config" => {
            let config = state.smb.get_config().await;
            Ok(serde_json::to_value(config).unwrap())
        }
        "set_enabled" => {
            let enabled: bool = extract_param(params, "enabled")?;
            state.smb.set_enabled(enabled).await?;
            Ok(Value::Bool(true))
        }
        "list_shares" => {
            let shares = state.smb.list_shares().await;
            Ok(serde_json::to_value(shares).unwrap())
        }
        "create_share" => {
            let share: SmbShare = serde_json::from_value(params.clone())
                .map_err(|e| RpcError::InvalidParams(e.to_string()))?;
            let id = state.smb.create_share(share).await?;
            Ok(serde_json::to_value(id).unwrap())
        }
        "update_share" => {
            let share: SmbShare = serde_json::from_value(params.clone())
                .map_err(|e| RpcError::InvalidParams(e.to_string()))?;
            state.smb.update_share(share).await?;
            Ok(Value::Bool(true))
        }
        "delete_share" => {
            let id: Uuid = extract_param(params, "id")?;
            state.smb.delete_share(id).await?;
            Ok(Value::Bool(true))
        }
        "list_connections" => {
            let connections = state.smb.list_connections().await?;
            Ok(serde_json::to_value(connections).unwrap())
        }
        "set_settings" => {
            let workgroup: String = extract_param(params, "workgroup")?;
            let server_string: String = extract_param(params, "server_string")?;
            state.smb.set_settings(workgroup, server_string).await?;
            Ok(Value::Bool(true))
        }
        "get_share" => {
            let id: Uuid = extract_param(params, "id")?;
            let share = state.smb.get_share(id).await;
            Ok(serde_json::to_value(share).unwrap())
        }
        "set_password" => {
            let username: String = extract_param(params, "username")?;
            let password: String = extract_param(params, "password")?;
            state.smb.set_password(&username, &password).await?;
            Ok(Value::Bool(true))
        }
        "delete_user" => {
            let username: String = extract_param(params, "username")?;
            state.smb.delete_user(&username).await?;
            Ok(Value::Bool(true))
        }
        "enable_user" => {
            let username: String = extract_param(params, "username")?;
            state.smb.enable_user(&username).await?;
            Ok(Value::Bool(true))
        }
        "disable_user" => {
            let username: String = extract_param(params, "username")?;
            state.smb.disable_user(&username).await?;
            Ok(Value::Bool(true))
        }
        "list_locks" => {
            let locks = state.smb.list_locks().await?;
            Ok(serde_json::to_value(locks).unwrap())
        }
        "list_shares_status" => {
            let status = state.smb.list_shares_status().await?;
            Ok(serde_json::to_value(status).unwrap())
        }
        "reload" => {
            state.smb.reload().await?;
            Ok(Value::Bool(true))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn dispatch_nfs(state: &AppState, method: &str, params: &Value) -> RpcResult<Value> {
    match method {
        "get_config" => {
            let config = state.nfs.get_config().await;
            Ok(serde_json::to_value(config).unwrap())
        }
        "set_enabled" => {
            let enabled: bool = extract_param(params, "enabled")?;
            state.nfs.set_enabled(enabled).await?;
            Ok(Value::Bool(true))
        }
        "list_exports" => {
            let exports = state.nfs.list_exports().await;
            Ok(serde_json::to_value(exports).unwrap())
        }
        "create_export" => {
            let export: NfsExport = serde_json::from_value(params.clone())
                .map_err(|e| RpcError::InvalidParams(e.to_string()))?;
            let id = state.nfs.create_export(export).await?;
            Ok(serde_json::to_value(id).unwrap())
        }
        "delete_export" => {
            let id: Uuid = extract_param(params, "id")?;
            state.nfs.delete_export(id).await?;
            Ok(Value::Bool(true))
        }
        "list_clients" => {
            let clients = state.nfs.list_clients().await?;
            Ok(serde_json::to_value(clients).unwrap())
        }
        "get_export" => {
            let id: Uuid = extract_param(params, "id")?;
            let export = state.nfs.get_export(id).await;
            Ok(serde_json::to_value(export).unwrap())
        }
        "update_export" => {
            let export: NfsExport = serde_json::from_value(params.clone())
                .map_err(|e| RpcError::InvalidParams(e.to_string()))?;
            state.nfs.update_export(export).await?;
            Ok(Value::Bool(true))
        }
        "list_active_exports" => {
            let exports = state.nfs.list_active_exports().await?;
            Ok(serde_json::to_value(exports).unwrap())
        }
        "reexport" => {
            state.nfs.reexport().await?;
            Ok(Value::Bool(true))
        }
        "unexport_all" => {
            state.nfs.unexport_all().await?;
            Ok(Value::Bool(true))
        }
        "export_temp" => {
            let path: String = extract_param(params, "path")?;
            let client: String = extract_param(params, "client")?;
            let options: String = extract_param(params, "options")?;
            state.nfs.export_temp(&path, &client, &options).await?;
            Ok(Value::Bool(true))
        }
        "unexport" => {
            let path: String = extract_param(params, "path")?;
            let client: String = extract_param(params, "client")?;
            state.nfs.unexport(&path, &client).await?;
            Ok(Value::Bool(true))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn dispatch_system(state: &AppState, method: &str, params: &Value) -> RpcResult<Value> {
    match method {
        "apply" => {
            let result = state.nix.apply().await?;
            Ok(serde_json::to_value(result).unwrap())
        }
        "dry_build" => {
            let result = state.nix.dry_build().await?;
            Ok(serde_json::to_value(result).unwrap())
        }
        "list_generations" => {
            let generations = state.nix.list_generations().await?;
            Ok(serde_json::to_value(generations).unwrap())
        }
        "rollback" => {
            let result = state.nix.rollback().await?;
            Ok(serde_json::to_value(result).unwrap())
        }
        "switch_generation" => {
            let id: u32 = extract_param(params, "id")?;
            let result = state.nix.switch_generation(id).await?;
            Ok(serde_json::to_value(result).unwrap())
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

fn extract_param<T: serde::de::DeserializeOwned>(params: &Value, key: &str) -> RpcResult<T> {
    params
        .get(key)
        .ok_or_else(|| RpcError::InvalidParams(format!("Missing parameter: {}", key)))
        .and_then(|v| {
            serde_json::from_value(v.clone())
                .map_err(|e| RpcError::InvalidParams(format!("Invalid {}: {}", key, e)))
        })
}

fn extract_param_opt<T: serde::de::DeserializeOwned>(params: &Value, key: &str) -> Option<T> {
    params
        .get(key)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}
