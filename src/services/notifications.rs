use crate::state::{NotificationConfig, SmtpEncryption};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub type NotifyResult<T> = Result<T, NotifyError>;

#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error("SMTP not configured")]
    NotConfigured,
    #[error("Failed to send email: {0}")]
    SendFailed(String),
}

pub struct NotificationService {
    config: NotificationConfig,
    hostname: String,
}

impl NotificationService {
    pub fn new(config: NotificationConfig, hostname: String) -> Self {
        Self { config, hostname }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
            && !self.config.smtp.server.is_empty()
            && !self.config.smtp.recipient.is_empty()
    }

    pub async fn send(&self, subject: &str, body: &str) -> NotifyResult<()> {
        if !self.is_enabled() {
            return Err(NotifyError::NotConfigured);
        }

        let full_subject = format!("[NixNAS - {}] {}", self.hostname, subject);
        let full_body = format!(
            "NixNAS Notification\nHost: {}\nTime: {}\n\n{}\n\n--\nThis is an automated message from NixNAS.",
            self.hostname,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            body
        );

        if Self::command_exists("msmtp").await {
            self.send_via_msmtp(&full_subject, &full_body).await
        } else if Self::command_exists("curl").await {
            self.send_via_curl(&full_subject, &full_body).await
        } else {
            Err(NotifyError::SendFailed(
                "No mail tool available (msmtp or curl)".to_string(),
            ))
        }
    }

    async fn command_exists(cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    async fn send_via_msmtp(&self, subject: &str, body: &str) -> NotifyResult<()> {
        let smtp = &self.config.smtp;

        let email = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}",
            smtp.sender, smtp.recipient, subject, body
        );

        let mut cmd = Command::new("msmtp");
        cmd.arg("--host")
            .arg(&smtp.server)
            .arg("--port")
            .arg(smtp.port.to_string())
            .arg("--from")
            .arg(&smtp.sender);

        match smtp.encryption {
            SmtpEncryption::StartTls => {
                cmd.arg("--tls=on").arg("--tls-starttls=on");
            }
            SmtpEncryption::Ssl => {
                cmd.arg("--tls=on").arg("--tls-starttls=off");
            }
            SmtpEncryption::None => {
                cmd.arg("--tls=off");
            }
        }

        if smtp.auth_required {
            cmd.arg("--auth=on")
                .arg("--user")
                .arg(&smtp.username)
                .arg("--passwordeval")
                .arg(format!("echo '{}'", smtp.password.replace('\'', "'\\''")));
        }

        cmd.arg(&smtp.recipient);
        if let Some(secondary) = &smtp.recipient_secondary
            && !secondary.is_empty()
        {
            cmd.arg(secondary);
        }

        cmd.stdin(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| NotifyError::SendFailed(e.to_string()))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(email.as_bytes())
                .await
                .map_err(|e| NotifyError::SendFailed(e.to_string()))?;
        }

        let status = child
            .wait()
            .await
            .map_err(|e| NotifyError::SendFailed(e.to_string()))?;
        if status.success() {
            Ok(())
        } else {
            Err(NotifyError::SendFailed("msmtp failed".to_string()))
        }
    }

    async fn send_via_curl(&self, subject: &str, body: &str) -> NotifyResult<()> {
        let smtp = &self.config.smtp;

        let email = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}",
            smtp.sender, smtp.recipient, subject, body
        );

        let temp_file = "/tmp/nixnas-email.txt";
        tokio::fs::write(temp_file, &email)
            .await
            .map_err(|e| NotifyError::SendFailed(e.to_string()))?;

        let url = match smtp.encryption {
            SmtpEncryption::Ssl => format!("smtps://{}:{}", smtp.server, smtp.port),
            _ => format!("smtp://{}:{}", smtp.server, smtp.port),
        };

        let mut cmd = Command::new("curl");
        cmd.arg("--url")
            .arg(&url)
            .arg("--mail-from")
            .arg(&smtp.sender)
            .arg("--mail-rcpt")
            .arg(&smtp.recipient);

        if let Some(secondary) = &smtp.recipient_secondary
            && !secondary.is_empty()
        {
            cmd.arg("--mail-rcpt").arg(secondary);
        }

        if smtp.auth_required {
            cmd.arg("--user")
                .arg(format!("{}:{}", smtp.username, smtp.password));
        }

        if smtp.encryption == SmtpEncryption::StartTls {
            cmd.arg("--ssl-reqd");
        }

        cmd.arg("--upload-file").arg(temp_file);

        let output = cmd
            .output()
            .await
            .map_err(|e| NotifyError::SendFailed(e.to_string()))?;
        let _ = tokio::fs::remove_file(temp_file).await;

        if output.status.success() {
            Ok(())
        } else {
            Err(NotifyError::SendFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ))
        }
    }

    #[allow(dead_code)]
    pub async fn notify_disk_space(&self, mountpoint: &str, usage: u8) -> NotifyResult<()> {
        if usage >= 95 && self.config.events.disk_space_critical {
            self.send(
                &format!("CRITICAL: Disk full on {}", mountpoint),
                &format!("Disk space critical on {}!\nUsage: {}%", mountpoint, usage),
            )
            .await
        } else if usage >= 80 && self.config.events.disk_space_warning {
            self.send(
                &format!("WARNING: Disk space low on {}", mountpoint),
                &format!("Disk space warning on {}.\nUsage: {}%", mountpoint, usage),
            )
            .await
        } else {
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub async fn notify_smart_error(&self, device: &str, msg: &str) -> NotifyResult<()> {
        if !self.config.events.smart_errors {
            return Ok(());
        }
        self.send(
            &format!("SMART Error: {}", device),
            &format!(
                "SMART error on {}.\nDetails: {}\n\nConsider replacing this disk.",
                device, msg
            ),
        )
        .await
    }

    #[allow(dead_code)]
    pub async fn notify_zfs_error(&self, pool: &str, status: &str) -> NotifyResult<()> {
        if !self.config.events.zfs_pool_errors {
            return Ok(());
        }
        self.send(
            &format!("ZFS Pool Error: {}", pool),
            &format!("ZFS pool '{}' has an issue.\nStatus: {}", pool, status),
        )
        .await
    }

    #[allow(dead_code)]
    pub async fn notify_service_failure(&self, service: &str) -> NotifyResult<()> {
        if !self.config.events.service_failures {
            return Ok(());
        }
        self.send(
            &format!("Service Failed: {}", service),
            &format!("Service '{}' stopped unexpectedly.", service),
        )
        .await
    }

    #[allow(dead_code)]
    pub async fn notify_high_temp(&self, device: &str, temp: i32) -> NotifyResult<()> {
        if !self.config.events.high_temperature {
            return Ok(());
        }
        self.send(
            &format!("High Temperature: {} at {}°C", device, temp),
            &format!("Device '{}' is running hot at {}°C!", device, temp),
        )
        .await
    }

    pub async fn send_test(&self) -> NotifyResult<()> {
        self.send(
            "Test Notification",
            "This is a test email from NixNAS.\n\nIf you received this, notifications are working!",
        )
        .await
    }
}
