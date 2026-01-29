use crate::commands::runner::{command_exists, run_ok};
use crate::error::CmdResult;

/// Check if smbpasswd is available.
#[allow(dead_code)]
pub async fn is_available() -> bool {
    command_exists("smbpasswd").await
}

/// Set or update a Samba user's password.
/// The user must already exist as a system user.
pub async fn set_password(username: &str, password: &str) -> CmdResult<()> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    // smbpasswd reads password from stdin when using -s flag
    let mut child = Command::new("smbpasswd")
        .args(["-s", "-a", username])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| crate::error::CommandError::Execution {
            command: "smbpasswd".to_string(),
            message: e.to_string(),
        })?;

    // smbpasswd expects the password twice
    let stdin = child.stdin.as_mut().unwrap();
    stdin
        .write_all(format!("{}\n{}\n", password, password).as_bytes())
        .await
        .map_err(|e| crate::error::CommandError::Execution {
            command: "smbpasswd".to_string(),
            message: e.to_string(),
        })?;

    let output =
        child
            .wait_with_output()
            .await
            .map_err(|e| crate::error::CommandError::Execution {
                command: "smbpasswd".to_string(),
                message: e.to_string(),
            })?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(crate::error::CommandError::Failed {
            command: "smbpasswd".to_string(),
            code: output.status.code().unwrap_or(-1),
            stderr: stderr.to_string(),
        })
    }
}

/// Enable a Samba user.
pub async fn enable_user(username: &str) -> CmdResult<()> {
    run_ok("smbpasswd", &["-e", username]).await?;
    Ok(())
}

/// Disable a Samba user.
pub async fn disable_user(username: &str) -> CmdResult<()> {
    run_ok("smbpasswd", &["-d", username]).await?;
    Ok(())
}

/// Delete a Samba user from the database.
pub async fn delete_user(username: &str) -> CmdResult<()> {
    run_ok("smbpasswd", &["-x", username]).await?;
    Ok(())
}

/// Check if a user exists in the Samba database.
#[allow(dead_code)]
pub async fn user_exists(username: &str) -> bool {
    // pdbedit -L lists all users
    if let Ok(output) = run_ok("pdbedit", &["-L"]).await {
        output.stdout.lines().any(|line| {
            line.split(':')
                .next()
                .map(|u| u == username)
                .unwrap_or(false)
        })
    } else {
        false
    }
}

/// List all Samba users.
#[allow(dead_code)]
pub async fn list_users() -> CmdResult<Vec<String>> {
    let output = run_ok("pdbedit", &["-L"]).await?;
    let users = output
        .stdout
        .lines()
        .filter_map(|line| line.split(':').next().map(|s| s.to_string()))
        .collect();
    Ok(users)
}
