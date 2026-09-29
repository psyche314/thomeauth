#![doc = include_str!("../README.md")]

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;
use zeroize::Zeroizing;

mod crypto;
pub mod response;
#[cfg(test)]
mod tests;

pub use response::*;

pub const DEFAULT_ENDPOINT: &str = "https://www.thomelua.com/thomeauth/api/v2/";
pub type Result<T> = std::result::Result<T, Error>;

/// Application credentials, supplied by the application's owner.
/// Keys are raw 32-byte public keys, not their hex-encoded strings.
/// This type deliberately does not implement Debug because it holds the API key.
pub struct Config {
    pub app_id: u64,
    pub api_key: String,
    pub x25519_public_key: [u8; 32],
    pub ed25519_public_key: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid client configuration: {0}")]
    Config(&'static str),
    #[error("connect before making requests")]
    NotConnected,
    #[error("session expired; explicitly reconnect")]
    SessionExpired,
    #[error("operating system randomness unavailable")]
    Random,
    #[error("cryptographic verification failed: {0}")]
    Crypto(&'static str),
    #[error("invalid protocol response: {0}")]
    Protocol(&'static str),
    #[error("system clock is before the Unix epoch or outside the protocol range")]
    Clock,
    #[error("HTTP transport failed: {0}")]
    Transport(#[from] Box<ureq::Error>),
    #[error("HTTP status {0}")]
    Http(u16),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("server rejected the request ({code}): {message}")]
    Server { code: i64, message: String },
    #[error("request rejected: {0}")]
    Rejected(String),
}

struct Session {
    id: String,
    transport: Zeroizing<[u8; 32]>,
    kami: Zeroizing<[u8; 32]>,
    expires: Instant,
}

/// Owns one encrypted session. Dropping or disconnecting clears its key buffers.
/// Use a separate client for each application/device/session combination.
pub struct Client {
    config: Config,
    fingerprint: String,
    endpoint: Url,
    http: ureq::Agent,
    verify_key: VerifyingKey,
    session: Option<Session>,
    heartbeat_due: Option<Instant>,
}

impl Client {
    /// Construct a client without performing network I/O.
    pub fn new(config: Config, fingerprint: impl Into<String>) -> Result<Self> {
        Self::with_http(config, fingerprint, DEFAULT_ENDPOINT, default_http())
    }

    /// Supply an endpoint and an HTTP agent for proxies, timeouts or testing.
    /// The caller must configure its agent not to follow cross-origin redirects.
    pub fn with_http(
        config: Config,
        fingerprint: impl Into<String>,
        endpoint: &str,
        http: ureq::Agent,
    ) -> Result<Self> {
        if config.app_id == 0 || config.api_key.is_empty() {
            return Err(Error::Config("app_id and api_key are required"));
        }
        let fingerprint = fingerprint.into();
        if fingerprint.is_empty() {
            return Err(Error::Config("device fingerprint is required"));
        }
        let mut endpoint =
            Url::parse(endpoint).map_err(|_| Error::Config("invalid endpoint URL"))?;
        if !matches!(endpoint.scheme(), "https" | "http")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::Config(
                "endpoint must be an HTTP(S) base URL without credentials, query or fragment",
            ));
        }
        endpoint.set_path(&format!("{}/", endpoint.path().trim_end_matches('/')));
        let verify_key = VerifyingKey::from_bytes(&config.ed25519_public_key)
            .map_err(|_| Error::Config("invalid Ed25519 public key"))?;
        Ok(Self {
            config,
            fingerprint,
            endpoint,
            http,
            verify_key,
            session: None,
            heartbeat_due: None,
        })
    }

    /// Replace the current session. Failed handshakes leave the client disconnected.
    pub fn connect(&mut self) -> Result<()> {
        self.disconnect();
        let started = Instant::now();
        let secret = Zeroizing::new(crypto::random::<32>()?);
        let public_hex = hex::encode(crypto::public(&secret));
        let init_key = crypto::exchange(
            &secret,
            self.config.x25519_public_key,
            b"k9Xp2mWqR7vLnJ4cYbA8dFe3H",
        )?;
        let payload = json!({"api_key": self.config.api_key, "device_fingerprint": self.fingerprint,
            "timestamp": timestamp()?, "nonce": hex::encode(crypto::random::<16>()?)});
        let request = json!({"app_id": self.config.app_id, "ephemeral_public_key": public_hex,
            "encrypted_data": crypto::encrypt(&init_key, &serde_json::to_vec(&payload)?)?});
        let response = self
            .http
            .post(self.url("session"))
            .send_json(&request)
            .map_err(Box::new)?;
        let data = self.envelope(response, &init_key)?;
        let handshake: Handshake = serde_json::from_value(data)?;
        if handshake.crypto_version != 2 || handshake.session_id.is_empty() {
            return Err(Error::Protocol("invalid session id or crypto version"));
        }
        if crypto::decode::<32>(&handshake.ed25519_public_key)? != self.config.ed25519_public_key {
            return Err(Error::Crypto("server changed the pinned signing key"));
        }
        let peer = crypto::decode(&handshake.server_ephemeral_public)?;
        let signed = format!("{}{}", handshake.server_ephemeral_public, public_hex);
        crypto::verify(
            &self.verify_key,
            signed.as_bytes(),
            &handshake.ephemeral_signature,
        )?;
        let root = crypto::exchange(&secret, peer, b"T5uZsG6wN1xKfQ9jMrC0hBv4P")?;
        let transport = crypto::derive(
            root.as_ref(),
            Some(b"aR3nV8kLpW5mX2qYjF7d"),
            b"xQ4vN9bK2wRj",
        )?;
        let kami = crypto::derive(
            root.as_ref(),
            Some(b"zE6cH1pT8sW3mJ5nR"),
            b"yF7gL4vD9kR2xNq",
        )?;
        let details: SessionDetails =
            serde_json::from_slice(&crypto::decrypt(&transport, &handshake.encrypted_session)?)?;
        if details.session_id != handshake.session_id || details.crypto_version != 2 {
            return Err(Error::Protocol("session proof does not match handshake"));
        }
        let ttl = details
            .real_expire_time
            .checked_sub(details.server_time)
            .ok_or(Error::Protocol("invalid session expiry"))?
            .min(details.session_timeout)
            .min(handshake.expires_in);
        let expires = deadline(started, Duration::from_secs(ttl))?;
        self.session = Some(Session {
            id: handshake.session_id,
            transport,
            kami,
            expires,
        });
        Ok(())
    }

    /// Forget the session and its heartbeat schedule locally; does not unbind a device.
    pub fn disconnect(&mut self) {
        self.session = None;
        self.heartbeat_due = None;
    }

    /// Remaining locally usable session lifetime, measured with a monotonic clock.
    pub fn session_remaining(&self) -> Option<Duration> {
        self.session
            .as_ref()
            .map(|s| s.expires.saturating_duration_since(Instant::now()))
    }

    /// Next heartbeat deadline after an alive response. A past deadline means send now.
    pub fn heartbeat_due(&self) -> Option<Instant> {
        self.session
            .as_ref()
            .filter(|s| s.expires > Instant::now())
            .and(self.heartbeat_due)
    }

    pub fn activate(&mut self, kami: &str) -> Result<Activation> {
        let encrypted = crypto::encrypt(&self.active()?.kami, kami.as_bytes())?;
        let body = self.call("activate", json!({"encrypted_kami": encrypted}))?;
        let result = self.nested(&body, "encrypted_result")?;
        require(&result, "success")?;
        require(&result, "verified")?;
        Ok(serde_json::from_value(result)?)
    }

    /// Validate an activated card using the hash returned by activation or check.
    pub fn validate(&mut self, kami_hash: &str) -> Result<Validation> {
        let body = self.call("use", json!({"kami_hash": kami_hash}))?;
        let result = self.nested(&body, "encrypted_result")?;
        require(&result, "valid")?;
        require(&result, "verified")?;
        Ok(serde_json::from_value(result)?)
    }

    pub fn check(&mut self, kami: &str) -> Result<CardStatus> {
        let mut body = self.call("check", json!({"kami": kami}))?;
        if body.get("encrypted_info").is_some() {
            let info = self.nested(&body, "encrypted_info")?;
            require(&info, "verified")?;
            body["status"] = Value::String(string(&info, "real_status")?.into());
            for key in [
                "kami_hash",
                "real_remaining_seconds",
                "real_remaining_hours",
            ] {
                if let Some(value) = info.get(key) {
                    body[key] = value.clone();
                }
            }
        } else if body.get("status").and_then(Value::as_str) == Some("activated") {
            return Err(Error::Protocol("activated card has no encrypted proof"));
        }
        Ok(serde_json::from_value(body)?)
    }

    pub fn unbind(&mut self, kami_hash: &str) -> Result<Unbind> {
        let body = self.call("unbind", json!({"kami_hash": kami_hash}))?;
        let result = self.nested(&body, "encrypted_result")?;
        require(&result, "success")?;
        require(&result, "verified")?;
        let result = serde_json::from_value(result)?;
        self.heartbeat_due = None;
        Ok(result)
    }

    /// verification is the optional map of card conditions documented by the server.
    pub fn announcements(
        &mut self,
        announcement_id: Option<u64>,
        verification: Option<&serde_json::Map<String, Value>>,
    ) -> Result<Vec<Announcement>> {
        let mut request = json!({});
        if let Some(id) = announcement_id {
            request["announcement_id"] = json!(id);
        }
        if let Some(verification) = verification {
            request["verification"] = json!(verification);
        }
        let body = self.call("announcements", request)?;
        let result = self.nested(&body, "encrypted_data")?;
        require(&result, "verified")?;
        let announcements = result
            .get("real_data")
            .and_then(|v| v.get("announcements"))
            .ok_or(Error::Protocol("missing verified announcements"))?;
        Ok(serde_json::from_value(announcements.clone())?)
    }

    pub fn check_update(&mut self, version_code: u64, version: &str) -> Result<Update> {
        let body = self.call(
            "update/check",
            json!({"version_code": version_code, "version": version}),
        )?;
        let update: Update = serde_json::from_value(body.clone())?;
        if update.need_update {
            require(&self.nested(&body, "encrypted_info")?, "update_verified")?;
        }
        Ok(update)
    }

    pub fn upload_device(&mut self, kami: &str) -> Result<DeviceUpload> {
        let body = self.call(
            "device/upload",
            json!({"kami": kami, "device_fingerprint": self.fingerprint}),
        )?;
        let result = self.nested(&body, "encrypted_result")?;
        require(&result, "success")?;
        require(&result, "verified")?;
        Ok(serde_json::from_value(result)?)
    }

    pub fn device_kamis(&mut self) -> Result<Vec<DeviceCard>> {
        let body = self.call(
            "device/kamis",
            json!({"device_fingerprint": self.fingerprint}),
        )?;
        if string(&body, "status")? != "success" {
            return Err(Error::Rejected(string(&body, "status")?.into()));
        }
        let kamis = body
            .get("kamis")
            .ok_or(Error::Protocol("missing device cards"))?;
        Ok(serde_json::from_value(kamis.clone())?)
    }

    /// Send one heartbeat. Transport failures keep the session until its deadline,
    /// with an immediately due retry. Terminal states disconnect; disabled stops
    /// scheduling while retaining the existing session until it expires.
    pub fn heartbeat(&mut self, kami_hash: &str) -> Result<Heartbeat> {
        let started = Instant::now();
        self.heartbeat_due = Some(started);
        let body = self.call("heartbeat", json!({"kami_hash": kami_hash}))?;
        let result = self.nested(&body, "encrypted_result")?;
        let heartbeat: Heartbeat = serde_json::from_value(result)?;
        match heartbeat.status.as_str() {
            "alive" => {
                let expires = heartbeat
                    .session_expires_at_ms
                    .ok_or(Error::Protocol("alive heartbeat without session expiry"))?;
                let ttl = expires
                    .checked_sub(heartbeat.server_time_ms)
                    .ok_or(Error::Protocol("invalid heartbeat expiry"))?;
                let interval = Duration::from_secs(heartbeat.heartbeat_interval_sec);
                if interval.is_zero() || interval >= Duration::from_millis(ttl) {
                    return Err(Error::Protocol(
                        "heartbeat interval must be less than session lifetime",
                    ));
                }
                let expires = deadline(started, Duration::from_millis(ttl))?;
                let due = started
                    .checked_add(interval)
                    .ok_or(Error::Protocol("heartbeat interval overflow"))?;
                self.session.as_mut().unwrap().expires = expires;
                self.heartbeat_due = Some(due);
            }
            "disabled" => self.heartbeat_due = None,
            _ => self.disconnect(),
        }
        Ok(heartbeat)
    }

    fn active(&self) -> Result<&Session> {
        let session = self.session.as_ref().ok_or(Error::NotConnected)?;
        if session.expires <= Instant::now() {
            return Err(Error::SessionExpired);
        }
        Ok(session)
    }

    fn url(&self, path: &str) -> String {
        // Only fixed relative endpoint names reach this method.
        self.endpoint
            .join(path)
            .expect("fixed endpoint path")
            .into()
    }

    fn call(&mut self, path: &str, mut data: Value) -> Result<Value> {
        data["timestamp"] = json!(timestamp()?);
        data["nonce"] = json!(hex::encode(crypto::random::<16>()?));
        let session = self.active()?;
        let request = self
            .http
            .post(self.url(path))
            .header("Content-Type", "application/json")
            .header("X-Crypto-Version", "2")
            .header("X-Session-Id", &session.id)
            .header(
                "X-Encrypted-Api-Key",
                crypto::encrypt(&session.transport, self.config.api_key.as_bytes())?,
            )
            .header(
                "X-Encrypted-Data",
                crypto::encrypt(&session.transport, &serde_json::to_vec(&data)?)?,
            );
        let response = request.send_empty().map_err(Box::new)?;
        let result = self.envelope(response, &session.transport);
        if matches!(result, Err(Error::Server { code: 1004, .. })) {
            self.disconnect();
        }
        result
    }

    fn envelope(
        &self,
        mut response: ureq::http::Response<ureq::Body>,
        key: &[u8; 32],
    ) -> Result<Value> {
        if !response.status().is_success() {
            return Err(Error::Http(response.status().as_u16()));
        }
        let bytes = response
            .body_mut()
            .with_config()
            .limit(2 * 1024 * 1024)
            .read_to_vec()
            .map_err(Box::new)?;
        let mut value: Value = serde_json::from_slice(&bytes)?;
        let object = value
            .as_object_mut()
            .ok_or(Error::Protocol("response is not an object"))?;
        let signature = object
            .remove("signature")
            .ok_or(Error::Protocol("missing response signature"))?;
        let signature = signature
            .as_str()
            .ok_or(Error::Protocol("invalid response signature"))?;
        crypto::verify(
            &self.verify_key,
            crypto::canonical(&value).as_bytes(),
            signature,
        )?;
        let code = value
            .get("code")
            .and_then(Value::as_i64)
            .ok_or(Error::Protocol("missing response code"))?;
        if code != 0 {
            return Err(Error::Server {
                code,
                message: value
                    .get("message")
                    .or_else(|| value.get("msg"))
                    .and_then(Value::as_str)
                    .unwrap_or("request failed")
                    .into(),
            });
        }
        let data = value
            .get("data")
            .ok_or(Error::Protocol("missing response data"))?;
        Ok(serde_json::from_slice(&crypto::decrypt(
            key,
            string(data, "encrypted_data")?,
        )?)?)
    }

    fn nested(&self, body: &Value, field: &'static str) -> Result<Value> {
        let key = &self.session.as_ref().ok_or(Error::NotConnected)?.transport;
        Ok(serde_json::from_slice(&crypto::decrypt(
            key,
            string(body, field)?,
        )?)?)
    }
}

fn default_http() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

fn timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Clock)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Clock)
}

fn deadline(started: Instant, ttl: Duration) -> Result<Instant> {
    let end = started
        .checked_add(ttl)
        .ok_or(Error::Protocol("session lifetime overflow"))?;
    if end <= Instant::now() {
        return Err(Error::SessionExpired);
    }
    Ok(end)
}

fn string<'a>(value: &'a Value, field: &'static str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(Error::Protocol(field))
}

fn require(value: &Value, flag: &'static str) -> Result<()> {
    match value.get(flag).and_then(Value::as_bool) {
        Some(true) => Ok(()),
        Some(false) => Err(Error::Rejected(
            value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or(flag)
                .into(),
        )),
        None => Err(Error::Protocol(flag)),
    }
}

#[derive(Deserialize)]
struct Handshake {
    session_id: String,
    expires_in: u64,
    server_ephemeral_public: String,
    ephemeral_signature: String,
    encrypted_session: String,
    ed25519_public_key: String,
    crypto_version: u64,
}

#[derive(Deserialize)]
struct SessionDetails {
    session_id: String,
    server_time: u64,
    real_expire_time: u64,
    session_timeout: u64,
    crypto_version: u64,
}
