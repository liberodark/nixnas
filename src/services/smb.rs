use crate::commands::runner::{run_json, run_ok};
use crate::error::{CmdResult, CommandError, RpcError, RpcResult};
use crate::state::{SmbConfig, SmbShare, StateManager};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// SMB service handler.
pub struct SmbService {
    state: Arc<StateManager>,
}

impl SmbService {
    pub fn new(state: Arc<StateManager>) -> Self {
        Self { state }
    }

    /// Get current SMB configuration.
    pub async fn get_config(&self) -> SmbConfig {
        self.state.get_smb().await
    }

    /// Enable or disable SMB service.
    pub async fn set_enabled(&self, enabled: bool) -> RpcResult<()> {
        self.state.set_smb_enabled(enabled).await?;
        Ok(())
    }

    /// Update SMB global settings.
    pub async fn set_settings(&self, workgroup: String, server_string: String) -> RpcResult<()> {
        self.state
            .set_smb_settings(workgroup, server_string)
            .await?;
        Ok(())
    }

    /// List all SMB shares.
    pub async fn list_shares(&self) -> Vec<SmbShare> {
        self.state.get_smb().await.shares
    }

    /// Get a share by ID.
    pub async fn get_share(&self, id: Uuid) -> Option<SmbShare> {
        self.state
            .get_smb()
            .await
            .shares
            .into_iter()
            .find(|s| s.id == id)
    }

    /// Create a new share.
    pub async fn create_share(&self, share: SmbShare) -> RpcResult<Uuid> {
        let path = std::path::Path::new(&share.path);
        if !path.exists() {
            tokio::fs::create_dir_all(path).await.map_err(|e| {
                RpcError::Internal(format!(
                    "Failed to create directory '{}': {}",
                    share.path, e
                ))
            })?;
        }

        self.state.add_smb_share(share).await
    }

    /// Update an existing share.
    pub async fn update_share(&self, share: SmbShare) -> RpcResult<()> {
        let path = std::path::Path::new(&share.path);
        if !path.exists() {
            tokio::fs::create_dir_all(path).await.map_err(|e| {
                RpcError::Internal(format!(
                    "Failed to create directory '{}': {}",
                    share.path, e
                ))
            })?;
        }

        self.state.update_smb_share(share).await
    }

    /// Delete a share.
    pub async fn delete_share(&self, id: Uuid) -> RpcResult<()> {
        self.state.delete_smb_share(id).await
    }

    /// Set SMB password for a user.
    pub async fn set_password(&self, username: &str, password: &str) -> CmdResult<()> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        // smbpasswd -a -s expects password twice on stdin
        let mut child = Command::new("smbpasswd")
            .args(["-a", "-s", username])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CommandError::Execution {
                command: "smbpasswd".to_string(),
                message: e.to_string(),
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            // smbpasswd expects password twice
            let input = format!("{}\n{}\n", password, password);
            stdin
                .write_all(input.as_bytes())
                .await
                .map_err(|e| CommandError::Execution {
                    command: "smbpasswd".to_string(),
                    message: e.to_string(),
                })?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| CommandError::Execution {
                command: "smbpasswd".to_string(),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(CommandError::Failed {
                command: "smbpasswd".to_string(),
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        Ok(())
    }

    /// Delete SMB user.
    pub async fn delete_user(&self, username: &str) -> CmdResult<()> {
        run_ok("smbpasswd", &["-x", username]).await?;
        Ok(())
    }

    /// Enable SMB user.
    pub async fn enable_user(&self, username: &str) -> CmdResult<()> {
        run_ok("smbpasswd", &["-e", username]).await?;
        Ok(())
    }

    /// Disable SMB user.
    pub async fn disable_user(&self, username: &str) -> CmdResult<()> {
        run_ok("smbpasswd", &["-d", username]).await?;
        Ok(())
    }

    /// Get current connections.
    pub async fn list_connections(&self) -> CmdResult<Vec<SmbConnection>> {
        #[derive(Debug, Deserialize)]
        struct SmbStatusOutput {
            #[serde(default)]
            sessions: Vec<SessionInfo>,
        }

        #[derive(Debug, Deserialize)]
        struct SessionInfo {
            session_id: String,
            #[serde(default)]
            username: String,
            #[serde(default)]
            remote_machine: String,
            #[serde(default)]
            hostname: String,
        }

        let output: SmbStatusOutput = run_json("smbstatus", &["-j"]).await?;

        Ok(output
            .sessions
            .into_iter()
            .map(|s| SmbConnection {
                session_id: s.session_id,
                username: s.username,
                remote_address: s.remote_machine,
                hostname: s.hostname,
            })
            .collect())
    }

    /// Get locked files.
    pub async fn list_locks(&self) -> CmdResult<Vec<SmbLock>> {
        #[derive(Debug, Deserialize)]
        struct SmbLocksOutput {
            #[serde(default)]
            locked_files: Vec<LockedFile>,
        }

        #[derive(Debug, Deserialize)]
        struct LockedFile {
            #[serde(default)]
            service_path: String,
            #[serde(default)]
            filename: String,
            #[serde(default)]
            opened_at: String,
        }

        let output: SmbLocksOutput = run_json("smbstatus", &["-L", "-j"]).await?;

        Ok(output
            .locked_files
            .into_iter()
            .map(|f| SmbLock {
                share_path: f.service_path,
                filename: f.filename,
                opened_at: f.opened_at,
            })
            .collect())
    }

    /// Get shares status.
    pub async fn list_shares_status(&self) -> CmdResult<Vec<SmbShareStatus>> {
        #[derive(Debug, Deserialize)]
        struct SmbSharesOutput {
            #[serde(default)]
            shares: Vec<ShareInfo>,
        }

        #[derive(Debug, Deserialize)]
        struct ShareInfo {
            service: String,
            #[serde(default)]
            pid: u32,
            #[serde(default)]
            machine: String,
            #[serde(default)]
            connected_at: String,
        }

        let output: SmbSharesOutput = run_json("smbstatus", &["-S", "-j"]).await?;

        Ok(output
            .shares
            .into_iter()
            .map(|s| SmbShareStatus {
                name: s.service,
                pid: s.pid,
                machine: s.machine,
                connected_at: s.connected_at,
            })
            .collect())
    }

    /// Reload Samba configuration (without full service restart).
    pub async fn reload(&self) -> CmdResult<()> {
        run_ok("smbcontrol", &["all", "reload-config"]).await?;
        Ok(())
    }
}

/// Active SMB connection.
#[derive(Debug, Clone, Serialize)]
pub struct SmbConnection {
    pub session_id: String,
    pub username: String,
    pub remote_address: String,
    pub hostname: String,
}

/// Locked file in SMB.
#[derive(Debug, Clone, Serialize)]
pub struct SmbLock {
    pub share_path: String,
    pub filename: String,
    pub opened_at: String,
}

/// Share status (connected clients).
#[derive(Debug, Clone, Serialize)]
pub struct SmbShareStatus {
    pub name: String,
    pub pid: u32,
    pub machine: String,
    pub connected_at: String,
}
