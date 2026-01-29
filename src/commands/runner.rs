use crate::error::{CmdResult, CommandError};
use serde::de::DeserializeOwned;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, error};

/// Output from a command execution.
#[derive(Debug)]
pub struct CommandOutput {
    pub success: bool,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Execute a command and return raw output.
pub async fn run(program: &str, args: &[&str]) -> CmdResult<CommandOutput> {
    debug!(program, ?args, "Executing command");

    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| CommandError::Execution {
            command: format_command(program, args),
            message: e.to_string(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);

    debug!(code, "Command completed");

    Ok(CommandOutput {
        success: output.status.success(),
        code,
        stdout,
        stderr,
    })
}

/// Execute a command and require success.
pub async fn run_ok(program: &str, args: &[&str]) -> CmdResult<CommandOutput> {
    let output = run(program, args).await?;

    if !output.success {
        error!(
            command = format_command(program, args),
            code = output.code,
            stderr = output.stderr,
            "Command failed"
        );
        return Err(CommandError::Failed {
            command: format_command(program, args),
            code: output.code,
            stderr: output.stderr,
        });
    }

    Ok(output)
}

/// Execute a command and parse JSON output.
pub async fn run_json<T: DeserializeOwned>(program: &str, args: &[&str]) -> CmdResult<T> {
    let output = run_ok(program, args).await?;

    serde_json::from_str(&output.stdout).map_err(|e| CommandError::Parse {
        command: format_command(program, args),
        message: e.to_string(),
    })
}

/// Execute a command and parse JSON output, ignoring exit code.
/// Useful for commands like smartctl that return non-zero exit codes
/// even when producing valid JSON output.
pub async fn run_json_ignore_exit<T: DeserializeOwned>(
    program: &str,
    args: &[&str],
) -> CmdResult<T> {
    let output = run(program, args).await?;

    // Log as debug instead of error for non-zero exit codes
    if !output.success {
        debug!(
            command = format_command(program, args),
            code = output.code,
            "Command returned non-zero exit code (may be normal)"
        );
    }

    serde_json::from_str(&output.stdout).map_err(|e| CommandError::Parse {
        command: format_command(program, args),
        message: e.to_string(),
    })
}

/// Execute a command and return stdout lines.
pub async fn run_lines(program: &str, args: &[&str]) -> CmdResult<Vec<String>> {
    let output = run_ok(program, args).await?;

    Ok(output
        .stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Execute a command and return tab-separated fields for each line.
pub async fn run_table(program: &str, args: &[&str]) -> CmdResult<Vec<Vec<String>>> {
    let output = run_ok(program, args).await?;

    Ok(output
        .stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| line.split('\t').map(String::from).collect())
        .collect())
}

/// Check if a command exists.
pub async fn command_exists(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

/// Format command for logging/error messages.
fn format_command(program: &str, args: &[&str]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{} {}", program, args.join(" "))
    }
}
