use crate::commands::zfs;
use crate::state::StateManager;
use std::sync::Arc;
use tokio::time::{Duration, interval};

/// Background replication service that executes scheduled replication tasks.
pub struct ReplicationService {
    state_manager: Arc<StateManager>,
}

impl ReplicationService {
    pub fn new(state_manager: Arc<StateManager>) -> Self {
        Self { state_manager }
    }

    /// Start the replication scheduler.
    /// Checks every 60 seconds if any task needs to run.
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                self.check_and_run().await;
            }
        });
    }

    async fn check_and_run(&self) {
        let tasks = self.state_manager.get_replication_tasks().await;
        let now = chrono::Utc::now();

        for task in tasks {
            if !task.enabled || task.status == "running" {
                continue;
            }

            let should_run = if task.last_sync.is_empty() {
                true
            } else if let Ok(last) = chrono::DateTime::parse_from_rfc3339(&task.last_sync) {
                let elapsed = now.signed_duration_since(last);
                elapsed.num_minutes() >= i64::from(task.interval_minutes)
            } else {
                true
            };

            if should_run {
                let state_manager = Arc::clone(&self.state_manager);
                let task_clone = task.clone();
                tokio::spawn(async move {
                    execute_replication(state_manager, task_clone).await;
                });
            }
        }
    }
}

/// Execute a single replication task.
pub async fn execute_replication(
    state_manager: Arc<StateManager>,
    task: crate::state::ReplicationTask,
) {
    let task_id = task.id;
    let task_name = task.name.clone();

    tracing::info!("Replication '{}': starting", task_name);

    if let Err(e) = state_manager
        .update_replication_status(task_id, "running", None, None)
        .await
    {
        tracing::error!(
            "Replication '{}': failed to update status: {}",
            task_name,
            e
        );
        return;
    }

    let snap_name = format!("nixnas-repl-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let full_snap = format!("{}@{}", task.source_dataset, snap_name);

    if let Err(e) = zfs::create_snapshot(&task.source_dataset, &snap_name).await {
        let err_msg = format!("Failed to create snapshot: {}", e);
        tracing::error!("Replication '{}': {}", task_name, err_msg);
        let _ = state_manager
            .update_replication_status(task_id, "error", None, Some(&err_msg))
            .await;
        return;
    }

    let incremental_from = if task.last_snapshot.is_empty() {
        None
    } else {
        Some(task.last_snapshot.clone())
    };

    let options = zfs::SendReceiveOptions {
        snapshot: full_snap.clone(),
        incremental_from,
        target_host: if task.transport == "local" {
            String::new()
        } else {
            task.target_host.clone()
        },
        target_dataset: task.target_dataset.clone(),
        ssh_port: if task.ssh_port == 22 {
            None
        } else {
            Some(task.ssh_port)
        },
        ssh_key: if task.ssh_key_path.is_empty() {
            None
        } else {
            Some(task.ssh_key_path.clone())
        },
        recursive: task.recursive,
        force_receive: task.force_receive,
        resumable: task.resumable,
    };

    match zfs::send_receive(&options).await {
        Ok(()) => {
            tracing::info!("Replication '{}': completed successfully", task_name);

            if !task.last_snapshot.is_empty()
                && let Err(e) = zfs::destroy_snapshot(&task.last_snapshot).await
            {
                tracing::warn!(
                    "Replication '{}': failed to clean up old snapshot '{}': {}",
                    task_name,
                    task.last_snapshot,
                    e
                );
            }

            let _ = state_manager
                .update_replication_status(task_id, "idle", Some(&full_snap), None)
                .await;
        }
        Err(e) => {
            let err_msg = format!("Send/receive failed: {}", e);
            tracing::error!("Replication '{}': {}", task_name, err_msg);

            if !task.last_snapshot.is_empty() {
                tracing::warn!(
                    "Replication '{}': incremental failed. You may need to delete the target \
                     dataset and let a full replication run, or clear last_snapshot.",
                    task_name
                );
            }

            let _ = zfs::destroy_snapshot(&full_snap).await;

            let _ = state_manager
                .update_replication_status(task_id, "error", None, Some(&err_msg))
                .await;
        }
    }
}
