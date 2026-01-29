#![allow(dead_code)]

use crate::commands::runner::{run, run_ok};
use crate::error::CommandError;
use serde::{Deserialize, Serialize};

/// ACL entry type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AclType {
    User,
    Group,
    Mask,
    Other,
}

impl std::fmt::Display for AclType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclType::User => write!(f, "u"),
            AclType::Group => write!(f, "g"),
            AclType::Mask => write!(f, "m"),
            AclType::Other => write!(f, "o"),
        }
    }
}

/// Permission level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AclPermission {
    /// No access (---)
    None,
    /// Read only (r--)
    Read,
    /// Read + Execute (r-x)
    ReadExecute,
    /// Read + Write (rw-)
    ReadWrite,
    /// Full access (rwx)
    Full,
}

impl AclPermission {
    /// Convert to rwx string for setfacl
    pub fn to_rwx(self) -> &'static str {
        match self {
            AclPermission::None => "---",
            AclPermission::Read => "r",
            AclPermission::ReadExecute => "rx",
            AclPermission::ReadWrite => "rw",
            AclPermission::Full => "rwx",
        }
    }

    /// Convert to display string (for UI)
    pub fn to_display(self) -> &'static str {
        match self {
            AclPermission::None => "---",
            AclPermission::Read => "r--",
            AclPermission::ReadExecute => "r-x",
            AclPermission::ReadWrite => "rw-",
            AclPermission::Full => "rwx",
        }
    }

    /// Convert to numeric permission
    pub fn to_numeric(self) -> u8 {
        match self {
            AclPermission::None => 0,
            AclPermission::Read => 4,
            AclPermission::ReadExecute => 5,
            AclPermission::ReadWrite => 6,
            AclPermission::Full => 7,
        }
    }

    /// Parse from rwx string
    pub fn from_rwx(s: &str) -> Self {
        let r = s.contains('r');
        let w = s.contains('w');
        let x = s.contains('x');

        match (r, w, x) {
            (true, true, true) => AclPermission::Full,
            (true, true, false) => AclPermission::ReadWrite,
            (true, false, true) => AclPermission::ReadExecute,
            (true, false, false) => AclPermission::Read,
            _ => AclPermission::None,
        }
    }

    /// Human-readable label
    pub fn label(&self) -> &'static str {
        match self {
            AclPermission::None => "No access",
            AclPermission::Read => "Read",
            AclPermission::ReadExecute => "Read/Execute",
            AclPermission::ReadWrite => "Read/Write",
            AclPermission::Full => "Full control",
        }
    }
}

/// A single ACL entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    /// Type: user, group, mask, other
    pub acl_type: AclType,
    /// Name (empty for owner/owning group/other)
    pub name: String,
    /// Permission
    pub permission: AclPermission,
    /// Is this a default ACL (for directories)
    pub is_default: bool,
}

impl AclEntry {
    /// Format as setfacl specification
    pub fn to_spec(&self) -> String {
        let prefix = if self.is_default { "d:" } else { "" };
        let name = if self.name.is_empty() {
            "".to_string()
        } else {
            self.name.clone()
        };

        format!(
            "{}{}:{}:{}",
            prefix,
            self.acl_type,
            name,
            self.permission.to_rwx()
        )
    }
}

/// Full ACL information for a path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclInfo {
    /// Path
    pub path: String,
    /// Owner user
    pub owner: String,
    /// Owner group
    pub group: String,
    /// ACL entries
    pub entries: Vec<AclEntry>,
    /// Default ACL entries (for directories)
    pub default_entries: Vec<AclEntry>,
}

/// Check if ACL tools are available
pub async fn is_available() -> bool {
    tokio::process::Command::new("which")
        .arg("getfacl")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if filesystem supports ACLs
pub async fn supports_acl(path: &str) -> bool {
    get_acl(path).await.is_ok()
}

/// Get ACL information for a path
pub async fn get_acl(path: &str) -> Result<AclInfo, CommandError> {
    let output = run("getfacl", &["-p", "-c", path]).await?;

    if !output.success {
        return Err(CommandError::Execution {
            command: format!("getfacl -p -c {}", path),
            message: output.stderr,
        });
    }

    parse_getfacl_output(path, &output.stdout)
}

/// Parse getfacl output
fn parse_getfacl_output(path: &str, output: &str) -> Result<AclInfo, CommandError> {
    let mut owner = String::new();
    let mut group = String::new();
    let mut entries = Vec::new();
    let mut default_entries = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            if line.starts_with("# owner:") {
                owner = line.trim_start_matches("# owner:").trim().to_string();
            } else if line.starts_with("# group:") {
                group = line.trim_start_matches("# group:").trim().to_string();
            }
            continue;
        }

        let is_default = line.starts_with("default:");
        let entry_str = if is_default {
            line.trim_start_matches("default:")
        } else {
            line
        };

        let parts: Vec<&str> = entry_str.split(':').collect();
        if parts.len() >= 3 {
            let acl_type = match parts[0] {
                "user" => AclType::User,
                "group" => AclType::Group,
                "mask" => AclType::Mask,
                "other" => AclType::Other,
                _ => continue,
            };

            let name = parts[1].to_string();
            let permission = AclPermission::from_rwx(parts[2]);

            let entry = AclEntry {
                acl_type,
                name,
                permission,
                is_default,
            };

            if is_default {
                default_entries.push(entry);
            } else {
                entries.push(entry);
            }
        }
    }

    Ok(AclInfo {
        path: path.to_string(),
        owner,
        group,
        entries,
        default_entries,
    })
}

/// Set ACL options
#[derive(Debug, Clone, Default)]
pub struct SetAclOptions {
    /// Apply recursively
    pub recursive: bool,
    /// Remove all extended ACL entries first
    pub replace: bool,
    /// Also set as default ACL (for directories)
    pub set_default: bool,
}

/// Set ACL entry on a path
pub async fn set_acl(
    path: &str,
    entry: &AclEntry,
    options: &SetAclOptions,
) -> Result<(), CommandError> {
    let mut args = Vec::new();

    if options.recursive {
        args.push("-R");
    }

    args.push("-m");
    let spec = entry.to_spec();
    args.push(&spec);

    let default_spec;
    if options.set_default && !entry.is_default {
        let mut default_entry = entry.clone();
        default_entry.is_default = true;
        default_spec = default_entry.to_spec();
        args.push("-m");
        args.push(&default_spec);
    }

    args.push(path);

    run_ok("setfacl", &args).await?;
    Ok(())
}

/// Set multiple ACL entries at once
pub async fn set_acl_batch(
    path: &str,
    entries: &[AclEntry],
    options: &SetAclOptions,
) -> Result<(), CommandError> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut args = Vec::new();

    if options.recursive {
        args.push("-R".to_string());
    }

    if options.replace {
        args.push("-b".to_string());
    }

    for entry in entries {
        args.push("-m".to_string());
        args.push(entry.to_spec());

        if options.set_default && !entry.is_default {
            let mut default_entry = entry.clone();
            default_entry.is_default = true;
            args.push("-m".to_string());
            args.push(default_entry.to_spec());
        }
    }

    args.push(path.to_string());

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_ok("setfacl", &args_ref).await?;
    Ok(())
}

/// Remove ACL entry from a path
pub async fn remove_acl(
    path: &str,
    acl_type: &AclType,
    name: &str,
    recursive: bool,
) -> Result<(), CommandError> {
    let mut args = Vec::new();

    if recursive {
        args.push("-R");
    }

    let spec = if name.is_empty() {
        format!("{}:", acl_type)
    } else {
        format!("{}:{}", acl_type, name)
    };

    args.push("-x");
    let spec_leaked = Box::leak(spec.into_boxed_str());
    args.push(spec_leaked);

    let default_spec = format!("d:{}:{}", acl_type, name);
    args.push("-x");
    let default_spec_leaked = Box::leak(default_spec.into_boxed_str());
    args.push(default_spec_leaked);

    args.push(path);

    run_ok("setfacl", &args).await?;
    Ok(())
}

/// Remove all extended ACLs from a path
pub async fn remove_all_acl(path: &str, recursive: bool) -> Result<(), CommandError> {
    let mut args = Vec::new();

    if recursive {
        args.push("-R");
    }

    args.push("-b"); // Remove all extended ACLs
    args.push(path);

    run_ok("setfacl", &args).await?;
    Ok(())
}

/// Apply ACLs for shared folders
/// Sets user/group permissions based on privilege list
pub async fn apply_shared_folder_acl(
    path: &str,
    privileges: &[(String, bool, AclPermission)], // (name, is_group, permission)
    recursive: bool,
) -> Result<(), CommandError> {
    let entries: Vec<AclEntry> = privileges
        .iter()
        .map(|(name, is_group, perm)| AclEntry {
            acl_type: if *is_group {
                AclType::Group
            } else {
                AclType::User
            },
            name: name.clone(),
            permission: *perm,
            is_default: false,
        })
        .collect();

    let options = SetAclOptions {
        recursive,
        replace: true,     // Replace existing ACLs
        set_default: true, // Set default ACLs for new files
    };

    set_acl_batch(path, &entries, &options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_to_rwx() {
        assert_eq!(AclPermission::None.to_rwx(), "---");
        assert_eq!(AclPermission::Read.to_rwx(), "r");
        assert_eq!(AclPermission::ReadWrite.to_rwx(), "rw");
        assert_eq!(AclPermission::Full.to_rwx(), "rwx");
    }

    #[test]
    fn test_permission_from_rwx() {
        assert_eq!(AclPermission::from_rwx("rwx"), AclPermission::Full);
        assert_eq!(AclPermission::from_rwx("rw-"), AclPermission::ReadWrite);
        assert_eq!(AclPermission::from_rwx("r--"), AclPermission::Read);
        assert_eq!(AclPermission::from_rwx("---"), AclPermission::None);
    }

    #[test]
    fn test_entry_to_spec() {
        let entry = AclEntry {
            acl_type: AclType::User,
            name: "john".to_string(),
            permission: AclPermission::ReadWrite,
            is_default: false,
        };
        assert_eq!(entry.to_spec(), "u:john:rw");

        let default_entry = AclEntry {
            acl_type: AclType::Group,
            name: "users".to_string(),
            permission: AclPermission::Read,
            is_default: true,
        };
        assert_eq!(default_entry.to_spec(), "d:g:users:r");
    }

    #[test]
    fn test_parse_getfacl() {
        let output = r#"# file: /data/share
# owner: root
# group: users
user::rwx
user:john:rw-
group::r-x
group:admins:rwx
mask::rwx
other::---
default:user::rwx
default:group::r-x
default:other::---
"#;

        let info = parse_getfacl_output("/data/share", output).unwrap();
        assert_eq!(info.owner, "root");
        assert_eq!(info.group, "users");
        assert_eq!(info.entries.len(), 6);
        assert_eq!(info.default_entries.len(), 3);

        let john = info.entries.iter().find(|e| e.name == "john").unwrap();
        assert_eq!(john.acl_type, AclType::User);
        assert_eq!(john.permission, AclPermission::ReadWrite);
    }
}
