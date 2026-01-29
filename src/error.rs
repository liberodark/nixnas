use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Main error type for RPC operations.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("Method not found: {0}")]
    MethodNotFound(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Command failed: {0}")]
    Command(#[from] CommandError),

    #[error("State error: {0}")]
    State(#[from] StateError),

    #[error("Nix generation error: {0}")]
    NixGen(#[from] NixError),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl RpcError {
    pub fn code(&self) -> i32 {
        match self {
            Self::ServiceNotFound(_) => 404,
            Self::MethodNotFound(_) => 404,
            Self::InvalidParams(_) => 400,
            Self::Unauthorized => 401,
            Self::Command(_) => 500,
            Self::State(_) => 500,
            Self::NixGen(_) => 500,
            Self::Internal(_) => 500,
        }
    }
}

/// Error response sent to clients.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: i32,
    pub message: String,
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        let status = match &self {
            RpcError::ServiceNotFound(_) | RpcError::MethodNotFound(_) => StatusCode::NOT_FOUND,
            RpcError::InvalidParams(_) => StatusCode::BAD_REQUEST,
            RpcError::Unauthorized => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = ErrorResponse {
            success: false,
            error: ErrorDetail {
                code: self.code(),
                message: self.to_string(),
            },
        };

        (status, Json(body)).into_response()
    }
}

/// Error type for command execution.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("Failed to execute '{command}': {message}")]
    Execution { command: String, message: String },

    #[error("Command '{command}' failed with code {code}: {stderr}")]
    Failed {
        command: String,
        code: i32,
        stderr: String,
    },

    #[error("Failed to parse output from '{command}': {message}")]
    Parse { command: String, message: String },

    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Operation not supported: {0}")]
    NotSupported(String),
}

/// Error type for state management.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Failed to read state file: {0}")]
    Read(String),

    #[error("Failed to write state file: {0}")]
    Write(String),

    #[error("Failed to parse state: {0}")]
    Parse(String),

    #[error("Item not found: {0}")]
    NotFound(String),

    #[error("Item already exists: {0}")]
    AlreadyExists(String),
}

/// Error type for Nix generation.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum NixError {
    #[error("Failed to generate Nix config: {0}")]
    Generation(String),

    #[error("Failed to write Nix file: {0}")]
    Write(String),

    #[error("nixos-rebuild failed: {0}")]
    Rebuild(String),

    #[error("Dry-run failed: {0}")]
    DryRun(String),
}

/// Result type alias for RPC operations.
pub type RpcResult<T> = Result<T, RpcError>;

/// Result type alias for command operations.
pub type CmdResult<T> = Result<T, CommandError>;
