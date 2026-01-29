use crate::error::RpcError;
use crate::state::{AuthConfig, StateManager};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Configuration for login rate limiting
const MAX_ATTEMPTS: usize = 5; // Max failed attempts before lockout
const ATTEMPT_WINDOW_SECS: u64 = 900; // 15 minutes window for counting attempts
const LOCKOUT_DURATION_SECS: u64 = 180; // 3 minutes lockout

/// Tracks login attempts for rate limiting
#[derive(Debug, Default)]
struct AttemptRecord {
    attempts: Vec<Instant>,
    locked_until: Option<Instant>,
}

/// Rate limiter for login attempts
pub struct LoginRateLimiter {
    records: RwLock<HashMap<IpAddr, AttemptRecord>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }

    /// Check if an IP is allowed to attempt login
    /// Returns Ok(()) if allowed, Err(remaining_seconds) if locked out
    pub async fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let mut records = self.records.write().await;
        let record = records.entry(ip).or_default();
        let now = Instant::now();

        if let Some(locked_until) = record.locked_until {
            if now < locked_until {
                let remaining = (locked_until - now).as_secs();
                tracing::warn!(
                    "Login attempt from locked IP {}: {} seconds remaining",
                    ip,
                    remaining
                );
                return Err(remaining);
            } else {
                // Lockout expired, clear it
                record.locked_until = None;
                record.attempts.clear();
            }
        }

        // Clean old attempts outside the window
        let window_start = now - std::time::Duration::from_secs(ATTEMPT_WINDOW_SECS);
        record.attempts.retain(|&t| t > window_start);

        Ok(())
    }

    /// Record a failed login attempt
    pub async fn record_failure(&self, ip: IpAddr) {
        let mut records = self.records.write().await;
        let record = records.entry(ip).or_default();
        let now = Instant::now();

        record.attempts.push(now);

        if record.attempts.len() >= MAX_ATTEMPTS {
            record.locked_until = Some(now + std::time::Duration::from_secs(LOCKOUT_DURATION_SECS));
            tracing::warn!(
                "IP {} locked out after {} failed attempts (lockout: {} seconds)",
                ip,
                MAX_ATTEMPTS,
                LOCKOUT_DURATION_SECS
            );
        } else {
            tracing::info!(
                "Failed login attempt from {} ({}/{} attempts)",
                ip,
                record.attempts.len(),
                MAX_ATTEMPTS
            );
        }
    }

    /// Clear failed attempts after successful login
    pub async fn clear(&self, ip: IpAddr) {
        let mut records = self.records.write().await;
        records.remove(&ip);
    }

    /// Get the number of recent failed attempts for an IP
    pub async fn get_attempt_count(&self, ip: IpAddr) -> usize {
        let records = self.records.read().await;
        records.get(&ip).map(|r| r.attempts.len()).unwrap_or(0)
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// JWT claims structure with IP for session binding
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject (username)
    pub exp: i64,           // Expiration time
    pub iat: i64,           // Issued at
    pub ip: Option<String>, // IP address for session binding
}

/// Authentication manager.
pub struct AuthManager {
    state: Arc<StateManager>,
    rate_limiter: LoginRateLimiter,
}

impl AuthManager {
    pub fn new(state: Arc<StateManager>) -> Self {
        Self {
            state,
            rate_limiter: LoginRateLimiter::new(),
        }
    }

    /// Get reference to rate limiter
    pub fn rate_limiter(&self) -> &LoginRateLimiter {
        &self.rate_limiter
    }

    /// Hash a password using Argon2.
    pub fn hash_password(password: &str) -> Result<String, RpcError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| RpcError::Internal(format!("Failed to hash password: {}", e)))
    }

    /// Verify a password against a hash.
    pub fn verify_password(password: &str, hash: &str) -> bool {
        if hash.is_empty() {
            return false;
        }

        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    /// Check rate limit for an IP address
    pub async fn check_rate_limit(&self, ip: IpAddr) -> Result<(), u64> {
        self.rate_limiter.check(ip).await
    }

    /// Authenticate user and return JWT token.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        ip: Option<IpAddr>,
    ) -> Result<String, RpcError> {
        if username != "admin" {
            tracing::warn!(
                "Login attempt with unknown user '{}' from {:?}",
                username,
                ip
            );
            return Err(RpcError::Unauthorized);
        }

        let auth = self.state.get_auth().await;

        if auth.admin_password_hash.is_empty() {
            // First login - set password
            let hash = Self::hash_password(password)?;
            self.state
                .set_auth(AuthConfig {
                    admin_password_hash: hash,
                    jwt_secret: auth.jwt_secret.clone(),
                })
                .await
                .map_err(|e| RpcError::Internal(e.to_string()))?;

            tracing::info!("Initial admin password set from {:?}", ip);
        } else if !Self::verify_password(password, &auth.admin_password_hash) {
            if let Some(ip_addr) = ip {
                self.rate_limiter.record_failure(ip_addr).await;
            }
            return Err(RpcError::Unauthorized);
        }

        if let Some(ip_addr) = ip {
            self.rate_limiter.clear(ip_addr).await;
            tracing::info!("Successful login for '{}' from {}", username, ip_addr);
        }

        self.generate_token(username, &auth.jwt_secret, ip)
    }

    /// Change admin password.
    pub async fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), RpcError> {
        let auth = self.state.get_auth().await;

        if !auth.admin_password_hash.is_empty()
            && !Self::verify_password(current_password, &auth.admin_password_hash)
        {
            return Err(RpcError::Unauthorized);
        }

        let new_hash = Self::hash_password(new_password)?;
        self.state
            .set_auth(AuthConfig {
                admin_password_hash: new_hash,
                jwt_secret: auth.jwt_secret,
            })
            .await
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        tracing::info!("Admin password changed");
        Ok(())
    }

    /// Generate a JWT token with optional IP binding.
    fn generate_token(
        &self,
        username: &str,
        secret: &str,
        ip: Option<IpAddr>,
    ) -> Result<String, RpcError> {
        let now = Utc::now();
        let exp = now + Duration::hours(24);

        let claims = Claims {
            sub: username.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            ip: ip.map(|i| i.to_string()),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .map_err(|e| RpcError::Internal(format!("Failed to generate token: {}", e)))
    }

    /// Validate a JWT token and optionally check IP.
    pub async fn validate_token(&self, token: &str) -> Result<Claims, RpcError> {
        let auth = self.state.get_auth().await;

        decode::<Claims>(
            token,
            &DecodingKey::from_secret(auth.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|_| RpcError::Unauthorized)
    }

    /// Validate token with IP check
    /// Reserved for future use - can be enabled for stricter session security
    #[allow(dead_code)]
    pub async fn validate_token_with_ip(
        &self,
        token: &str,
        request_ip: Option<IpAddr>,
    ) -> Result<Claims, RpcError> {
        let claims = self.validate_token(token).await?;

        // If token has IP and request has IP, they must match
        if let (Some(token_ip), Some(req_ip)) = (&claims.ip, request_ip)
            && token_ip != &req_ip.to_string()
        {
            tracing::warn!(
                "Session IP mismatch for user '{}': token={}, request={}",
                claims.sub,
                token_ip,
                req_ip
            );
            return Err(RpcError::Unauthorized);
        }

        Ok(claims)
    }

    /// Check if initial setup is required (no password set).
    pub async fn needs_setup(&self) -> bool {
        let auth = self.state.get_auth().await;
        auth.admin_password_hash.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "test_password_123";
        let hash = AuthManager::hash_password(password).unwrap();

        assert!(AuthManager::verify_password(password, &hash));
        assert!(!AuthManager::verify_password("wrong_password", &hash));
    }

    #[test]
    fn test_empty_hash_fails() {
        assert!(!AuthManager::verify_password("any", ""));
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        assert!(limiter.check(ip).await.is_ok());

        for _ in 0..MAX_ATTEMPTS {
            limiter.record_failure(ip).await;
        }

        assert!(limiter.check(ip).await.is_err());

        limiter.clear(ip).await;
        assert!(limiter.check(ip).await.is_ok());
    }
}
