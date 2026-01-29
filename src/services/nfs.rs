use crate::commands::runner::{run_lines, run_ok};
use crate::error::{CmdResult, RpcError, RpcResult};
use crate::state::{NfsClient, NfsConfig, NfsExport, StateManager};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

/// NFS service handler.
pub struct NfsService {
    state: Arc<StateManager>,
}

impl NfsService {
    pub fn new(state: Arc<StateManager>) -> Self {
        Self { state }
    }

    /// Get current NFS configuration.
    pub async fn get_config(&self) -> NfsConfig {
        self.state.get_nfs().await
    }

    /// Enable or disable NFS service.
    pub async fn set_enabled(&self, enabled: bool) -> RpcResult<()> {
        self.state.set_nfs_enabled(enabled).await?;
        Ok(())
    }

    /// List all NFS exports.
    pub async fn list_exports(&self) -> Vec<NfsExport> {
        self.state.get_nfs().await.exports
    }

    /// Get an export by ID.
    pub async fn get_export(&self, id: Uuid) -> Option<NfsExport> {
        self.state
            .get_nfs()
            .await
            .exports
            .into_iter()
            .find(|e| e.id == id)
    }

    /// Create a new export.
    pub async fn create_export(&self, export: NfsExport) -> RpcResult<Uuid> {
        let path = std::path::Path::new(&export.path);
        if !path.exists() {
            tokio::fs::create_dir_all(path).await.map_err(|e| {
                RpcError::Internal(format!(
                    "Failed to create directory '{}': {}",
                    export.path, e
                ))
            })?;
        }

        self.state.add_nfs_export(export).await
    }

    /// Update an existing export.
    pub async fn update_export(&self, export: NfsExport) -> RpcResult<()> {
        let path = std::path::Path::new(&export.path);
        if !path.exists() {
            tokio::fs::create_dir_all(path).await.map_err(|e| {
                RpcError::Internal(format!(
                    "Failed to create directory '{}': {}",
                    export.path, e
                ))
            })?;
        }

        self.state.update_nfs_export(export).await
    }

    /// Delete an export.
    pub async fn delete_export(&self, id: Uuid) -> RpcResult<()> {
        self.state.delete_nfs_export(id).await
    }

    /// List connected NFS clients.
    pub async fn list_clients(&self) -> CmdResult<Vec<NfsClientConnection>> {
        let lines = run_lines("showmount", &["-a", "--no-headers"]).await?;

        let clients = lines
            .iter()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 2 {
                    Some(NfsClientConnection {
                        client: parts[0].to_string(),
                        export: parts[1].to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(clients)
    }

    /// List currently exported paths.
    pub async fn list_active_exports(&self) -> CmdResult<Vec<ActiveNfsExport>> {
        let lines = run_lines("exportfs", &["-v"]).await?;

        let mut exports = Vec::new();
        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                exports.push(ActiveNfsExport {
                    path: parts[0].to_string(),
                    client: parts[1].to_string(),
                    options: parts.get(2).map(|s| s.to_string()).unwrap_or_default(),
                });
            }
        }

        Ok(exports)
    }

    /// Re-export all exports (refresh).
    pub async fn reexport(&self) -> CmdResult<()> {
        run_ok("exportfs", &["-ra"]).await?;
        Ok(())
    }

    /// Unexport all paths.
    pub async fn unexport_all(&self) -> CmdResult<()> {
        run_ok("exportfs", &["-ua"]).await?;
        Ok(())
    }

    /// Export a specific path to a client (temporary, not persisted).
    pub async fn export_temp(&self, path: &str, client: &str, options: &str) -> CmdResult<()> {
        let export_spec = format!("{}:{}", client, path);
        run_ok("exportfs", &["-o", options, &export_spec]).await?;
        Ok(())
    }

    /// Unexport a specific path from a client.
    pub async fn unexport(&self, path: &str, client: &str) -> CmdResult<()> {
        let export_spec = format!("{}:{}", client, path);
        run_ok("exportfs", &["-u", &export_spec]).await?;
        Ok(())
    }
}

/// Connected NFS client.
#[derive(Debug, Clone, Serialize)]
pub struct NfsClientConnection {
    pub client: String,
    pub export: String,
}

/// Active NFS export from exportfs.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveNfsExport {
    pub path: String,
    pub client: String,
    pub options: String,
}

#[allow(dead_code)]
impl NfsClient {
    /// Create a read-only client.
    pub fn read_only(host: String) -> Self {
        Self {
            host,
            options: vec![
                "ro".to_string(),
                "sync".to_string(),
                "no_subtree_check".to_string(),
            ],
        }
    }

    /// Create a read-write client.
    pub fn read_write(host: String) -> Self {
        Self {
            host,
            options: vec![
                "rw".to_string(),
                "sync".to_string(),
                "no_subtree_check".to_string(),
            ],
        }
    }

    /// Add root squash option.
    pub fn with_root_squash(mut self) -> Self {
        self.options.push("root_squash".to_string());
        self
    }

    /// Add no root squash option.
    pub fn with_no_root_squash(mut self) -> Self {
        self.options.push("no_root_squash".to_string());
        self
    }
}
