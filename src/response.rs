//! Response fields follow the protocol's names and units. Optional fields stay
//! optional; a missing expiry is never interpreted as zero or as a grant.

use serde::Deserialize;
use serde_json::Value;

/// Confirmed activation. This contains a credential and does not implement Debug.
#[derive(Deserialize)]
pub struct Activation {
    pub kami_hash: String,
    pub activation_time: u64,
    pub real_expire_hours: Option<i64>,
    pub real_expire_at: Option<String>,
    pub is_permanent: bool,
    pub device_limit: i64,
    pub check_device: bool,
    pub card_type: String,
}

/// Confirmed validation, decoded from encrypted_result rather than decoy fields.
#[derive(Debug, Deserialize)]
pub struct Validation {
    pub real_remaining_seconds: Option<i64>,
    pub real_remaining_hours: Option<f64>,
    pub real_expire_at: Option<String>,
    pub is_permanent: bool,
    pub validation_time: u64,
    pub device_count: i64,
    pub device_limit: i64,
    pub check_device: bool,
    pub card_type: String,
}

/// Card state. Secret fields are present only when returned by the server.
#[derive(Deserialize)]
pub struct CardStatus {
    pub status: String,
    pub kami_hash: Option<String>,
    pub real_remaining_seconds: Option<i64>,
    pub real_remaining_hours: Option<f64>,
    pub card_type: Option<String>,
    pub is_permanent: Option<bool>,
    pub device_count: Option<i64>,
    pub device_limit: Option<i64>,
    pub is_device_registered: Option<bool>,
    pub unbind_limit: Option<i64>,
    pub unbind_count: Option<i64>,
    pub unbind_remaining: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct Unbind {
    pub unbind_time: u64,
    pub strategy: UnbindStrategy,
    pub unbind_limit: i64,
    pub consume_unbind_count: bool,
}

#[derive(Debug, Deserialize)]
pub struct UnbindStrategy {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: f64,
}

#[derive(Debug, Deserialize)]
pub struct Announcement {
    pub id: u64,
    pub title: String,
    pub content: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub priority: i64,
    pub show_once: bool,
    pub has_conditions: bool,
    pub conditions_count: u64,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct Update {
    pub need_update: bool,
    pub current_version: Option<String>,
    pub latest_version: Option<String>,
    pub latest_version_code: Option<u64>,
    /// Vendor-provided release metadata, including download URL and changelog.
    pub update_info: Option<Value>,
    #[serde(default)]
    pub all_updates: Vec<Value>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceUpload {
    pub main_kami_id: u64,
    pub total_processed: u64,
    pub timestamp: u64,
}

/// Device-bound credentials. Intentionally does not implement Debug.
#[derive(Deserialize)]
pub struct DeviceCard {
    pub kami: String,
    pub kami_hash: String,
    pub remaining_hours: f64,
    pub expire_at: String,
    pub last_used_at: String,
}

/// Heartbeat timestamps are milliseconds; other endpoints use seconds.
/// Unknown statuses are preserved as strings and are treated as terminal.
#[derive(Debug, Deserialize)]
pub struct Heartbeat {
    pub status: String,
    pub message: String,
    pub server_time_ms: u64,
    pub session_expires_at_ms: Option<u64>,
    pub kami_expires_at_ms: Option<u64>,
    pub heartbeat_interval_sec: u64,
}
