use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    thread::{self, JoinHandle},
};

const API_KEY: &str = "unit-test-api-key";
const FINGERPRINT: &str = "unit-test-device";

fn config() -> Config {
    Config {
        app_id: 1,
        api_key: API_KEY.into(),
        x25519_public_key: crypto::public(&[42; 32]),
        ed25519_public_key: SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
    }
}

struct Request {
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Server {
    signing: SigningKey,
    transport: Option<Zeroizing<[u8; 32]>>,
    kami: Option<Zeroizing<[u8; 32]>>,
    nonces: HashSet<String>,
}

impl Server {
    fn sign(&self, mut body: Value) -> Value {
        body["signature"] = json!(hex::encode(
            self.signing
                .sign(crypto::canonical(&body).as_bytes())
                .to_bytes()
        ));
        body
    }

    fn seal(&self, data: Value) -> Value {
        self.sign(json!({"code": 0, "data": {"encrypted_data": crypto::encrypt(self.transport.as_ref().unwrap(), &serde_json::to_vec(&data).unwrap()).unwrap()}}))
    }

    fn nested(&self, name: &str, data: Value) -> Value {
        let mut body = json!({"status": "deliberately-not-authoritative"});
        body[name] = json!(
            crypto::encrypt(
                self.transport.as_ref().unwrap(),
                &serde_json::to_vec(&data).unwrap()
            )
            .unwrap()
        );
        self.seal(body)
    }

    fn handshake(&mut self, request: &Request) -> Value {
        self.handshake_with(request, |_, _| {})
    }

    fn handshake_with(
        &mut self,
        request: &Request,
        adjust: impl FnOnce(&mut Value, &mut Value),
    ) -> Value {
        assert_eq!(request.path, "/api/v2/session");
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["app_id"], 1);
        let client_hex = body["ephemeral_public_key"].as_str().unwrap();
        let client = crypto::decode(client_hex).unwrap();
        let init = crypto::exchange(&[42; 32], client, b"k9Xp2mWqR7vLnJ4cYbA8dFe3H").unwrap();
        let plain: Value = serde_json::from_slice(
            &crypto::decrypt(&init, body["encrypted_data"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(plain["api_key"], API_KEY);
        assert_eq!(plain["device_fingerprint"], FINGERPRINT);
        self.check_fresh(&plain);
        let server_hex = hex::encode(crypto::public(&[44; 32]));
        let signed = format!("{server_hex}{client_hex}");
        let root = crypto::exchange(&[44; 32], client, b"T5uZsG6wN1xKfQ9jMrC0hBv4P").unwrap();
        self.transport = Some(
            crypto::derive(
                root.as_ref(),
                Some(b"aR3nV8kLpW5mX2qYjF7d"),
                b"xQ4vN9bK2wRj",
            )
            .unwrap(),
        );
        self.kami = Some(
            crypto::derive(
                root.as_ref(),
                Some(b"zE6cH1pT8sW3mJ5nR"),
                b"yF7gL4vD9kR2xNq",
            )
            .unwrap(),
        );
        let mut details = json!({"session_id": "test-session", "server_time": 1700000000_u64,
            "real_expire_time": 1700000100_u64, "session_timeout": 100, "crypto_version": 2});
        let mut data = json!({"session_id": "test-session", "expires_in": 100, "crypto_version": 2,
            "ed25519_public_key": hex::encode(self.signing.verifying_key().to_bytes()),
            "server_ephemeral_public": server_hex,
            "ephemeral_signature": hex::encode(self.signing.sign(signed.as_bytes()).to_bytes())});
        adjust(&mut data, &mut details);
        data["encrypted_session"] = json!(
            crypto::encrypt(
                self.transport.as_ref().unwrap(),
                &serde_json::to_vec(&details).unwrap()
            )
            .unwrap()
        );
        self.sign(json!({"code": 0, "data": {"encrypted_data": crypto::encrypt(&init, &serde_json::to_vec(&data).unwrap()).unwrap()}}))
    }

    fn check_fresh(&mut self, plain: &Value) {
        let timestamp = plain["timestamp"].as_u64().unwrap();
        assert!(timestamp > 1_000_000_000_000); // Requests use milliseconds.
        let nonce = plain["nonce"].as_str().unwrap();
        assert_eq!(hex::decode(nonce).unwrap().len(), 16);
        assert!(self.nonces.insert(nonce.into()));
    }

    fn request(&mut self, request: &Request) -> Value {
        assert!(request.body.is_empty());
        assert_eq!(request.headers["content-type"], "application/json");
        assert_eq!(request.headers["x-crypto-version"], "2");
        assert_eq!(request.headers["x-session-id"], "test-session");
        let key = self.transport.as_ref().unwrap();
        assert_eq!(
            crypto::decrypt(key, &request.headers["x-encrypted-api-key"])
                .unwrap()
                .as_slice(),
            API_KEY.as_bytes()
        );
        let body = serde_json::from_slice(
            &crypto::decrypt(key, &request.headers["x-encrypted-data"]).unwrap(),
        )
        .unwrap();
        self.check_fresh(&body);
        body
    }
}

fn mock(
    count: usize,
    mut respond: impl FnMut(usize, &Request, &mut Server) -> (u16, Value) + Send + 'static,
) -> (Client, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/api/v2", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let mut server = Server {
            signing: SigningKey::from_bytes(&[43; 32]),
            transport: None,
            kami: None,
            nonces: HashSet::new(),
        };
        for index in 0..count {
            let end = Instant::now() + Duration::from_secs(10);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < end, "mock request timed out");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            let parts: Vec<_> = first.split_whitespace().collect();
            assert_eq!(parts[0], "POST");
            let path = parts[1].into();
            let mut headers = HashMap::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.split_once(':').unwrap();
                headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
            }
            let length = headers
                .get("content-length")
                .map(|s| s.parse::<usize>().unwrap())
                .unwrap_or(0);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let (status, response) = respond(
                index,
                &Request {
                    path,
                    headers,
                    body,
                },
                &mut server,
            );
            let bytes = serde_json::to_vec(&response).unwrap();
            write!(socket, "HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
            let _ = socket.write_all(&bytes); // Limit tests intentionally close early.
        }
    });
    (
        Client::with_http(config(), FINGERPRINT, &endpoint, default_http()).unwrap(),
        worker,
    )
}

fn ok(value: Value) -> (u16, Value) {
    (200, value)
}

fn alive() -> Value {
    json!({"status": "alive", "message": "ok", "server_time_ms": 1700000000000_u64,
        "session_expires_at_ms": 1700000100000_u64, "kami_expires_at_ms": null, "heartbeat_interval_sec": 5})
}

#[test]
fn independent_crypto_vectors() {
    // AEAD and protocol HKDF fixtures were generated independently with Node's
    // OpenSSL-backed crypto module, not with the functions under test.
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let packet =
        "000102030405060708090a0bdd93676d4c56d034dfa34b96eb692e6c9937193f2e239bc676098cec6916";
    assert_eq!(
        crypto::decrypt(&key, packet).unwrap().as_slice(),
        b"ThomeAuth test"
    );
    assert_eq!(
        hex::encode(
            crypto::derive(&key, Some(b"aR3nV8kLpW5mX2qYjF7d"), b"xQ4vN9bK2wRj")
                .unwrap()
                .as_ref()
        ),
        "b1f24bccdb19bbfe4946cf0e5259ebd4e4a661e69a52e071eb4e7c2fa6343f38"
    );
    // RFC 5869 test case 1, first 32 output bytes.
    assert_eq!(
        hex::encode(
            crypto::derive(
                &[0x0b; 22],
                Some(&hex::decode("000102030405060708090a0b0c").unwrap()),
                &hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap()
            )
            .unwrap()
            .as_ref()
        ),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    );
    // RFC 7748 Alice public key.
    let secret =
        crypto::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
    assert_eq!(
        hex::encode(crypto::public(&secret)),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
}

#[test]
fn ciphertext_authentication_and_weak_keys() {
    let packet = crypto::encrypt(&[1; 32], b"message").unwrap();
    assert!(crypto::decrypt(&[2; 32], &packet).is_err());
    let mut bytes = hex::decode(&packet).unwrap();
    bytes[15] ^= 1;
    assert!(crypto::decrypt(&[1; 32], &hex::encode(bytes)).is_err());
    for malformed in ["", "00", "zz"] {
        assert!(crypto::decrypt(&[1; 32], malformed).is_err());
    }
    assert!(crypto::exchange(&[1; 32], [0; 32], b"test").is_err());
    let mut low_order = [0; 32];
    low_order[0] = 1;
    assert!(crypto::exchange(&[1; 32], low_order, b"test").is_err());
}

#[test]
fn canonicalization_covers_nested_objects_numbers_and_unicode() {
    let value: Value = serde_json::from_str(r#"{"z":-0.0,"b":[42.0,3.14,1e20,18446744073709551615],"a":{"中":"\n\u0001\\\"","a":true}}"#).unwrap();
    assert_eq!(
        crypto::canonical(&value),
        r#"{"a":{"a":true,"中":"\n\u0001\\\""},"b":[42,3.14,100000000000000000000,18446744073709551615],"z":0}"#
    );
    assert_eq!(
        crypto::canonical(&json!({"a":[],"b":{},"c":null})),
        r#"{"a":[],"b":{},"c":null}"#
    );
}

#[test]
fn endpoints_and_constructor_are_explicit() {
    for endpoint in [
        "ftp://localhost",
        "https://user:pass@localhost",
        "https://host/?q=x",
        "https://host/#x",
        "relative",
    ] {
        assert!(Client::with_http(config(), FINGERPRINT, endpoint, default_http()).is_err());
    }
    let mut client = Client::new(config(), FINGERPRINT).unwrap();
    assert_eq!(client.url("use"), format!("{DEFAULT_ENDPOINT}use"));
    assert!(matches!(client.validate("hash"), Err(Error::NotConnected)));
    assert_eq!(client.session_remaining(), None);
    assert_eq!(client.heartbeat_due(), None);
}

#[test]
fn handshake_uses_server_lifetime_not_local_wall_clock() {
    let (mut client, worker) = mock(1, |_, request, server| ok(server.handshake(request)));
    client.connect().unwrap();
    let remaining = client.session_remaining().unwrap();
    assert!(remaining > Duration::from_secs(90) && remaining <= Duration::from_secs(100));
    client.disconnect();
    assert!(client.session.is_none());
    worker.join().unwrap();
}

#[test]
fn handshake_rejects_bad_proofs_versions_keys_and_expiry() {
    for case in 0..7 {
        let (mut client, worker) = mock(1, move |_, request, server| {
            ok(server.handshake_with(request, |outer, inner| match case {
                0 => outer["ed25519_public_key"] = json!("00".repeat(32)),
                1 => outer["ephemeral_signature"] = json!("00".repeat(64)),
                2 => outer["crypto_version"] = json!(1),
                3 => inner["crypto_version"] = json!(1),
                4 => inner["session_id"] = json!("other-session"),
                5 => outer["expires_in"] = json!(0),
                _ => inner["real_expire_time"] = json!(1),
            }))
        });
        assert!(client.connect().is_err(), "case {case}");
        assert!(client.session.is_none());
        worker.join().unwrap();
    }
}

#[test]
fn failed_reconnect_does_not_keep_an_old_session() {
    let (mut client, worker) = mock(2, |index, request, server| {
        let mut response = server.handshake(request);
        if index == 1 {
            response["signature"] = json!("00".repeat(64));
        }
        ok(response)
    });
    client.connect().unwrap();
    assert!(client.connect().is_err());
    assert!(client.session.is_none());
    worker.join().unwrap();
}

#[test]
fn all_documented_endpoints_use_verified_inner_data() {
    let (mut client, worker) = mock(10, |index, request, server| {
        if index == 0 {
            return ok(server.handshake(request));
        }
        let body = server.request(request);
        let response = match request.path.as_str() {
            "/api/v2/activate" => {
                assert_eq!(
                    crypto::decrypt(
                        server.kami.as_ref().unwrap(),
                        body["encrypted_kami"].as_str().unwrap()
                    )
                    .unwrap()
                    .as_slice(),
                    b"card"
                );
                server.nested("encrypted_result", json!({"success":true,"verified":true,"kami_hash":"hash","activation_time":1700000000,
                    "real_expire_hours":24,"real_expire_at":"tomorrow","is_permanent":false,"device_limit":2,"check_device":true,"card_type":"hour"}))
            }
            "/api/v2/use" => {
                assert_eq!(body["kami_hash"], "hash");
                server.nested("encrypted_result", json!({"valid":true,"verified":true,"real_remaining_seconds":12,
                    "real_remaining_hours":0.0033,"real_expire_at":"soon","is_permanent":false,"validation_time":1700000000,
                    "device_count":1,"device_limit":2,"check_device":true,"card_type":"hour"}))
            }
            "/api/v2/check" => {
                assert_eq!(body["kami"], "card");
                server.nested("encrypted_info", json!({"verified":true,"kami_hash":"hash","real_status":"activated","real_remaining_seconds":12}))
            }
            "/api/v2/unbind" => {
                assert_eq!(body["kami_hash"], "hash");
                server.nested("encrypted_result", json!({"success":true,"verified":true,"unbind_time":1700000000,
                    "strategy":{"type":"no_change","value":0},"unbind_limit":2,"consume_unbind_count":true}))
            }
            "/api/v2/announcements" => {
                assert!(body.get("announcement_id").is_none());
                assert!(body.get("verification").is_none());
                server.nested("encrypted_data", json!({"verified":true,"real_data":{"announcements":[{"id":1,"title":"hello","content":"world",
                    "type":"info","priority":0,"show_once":false,"has_conditions":false,"conditions_count":0,"created_at":"today"}]}}))
            }
            "/api/v2/update/check" => {
                assert_eq!(body["version_code"], 1);
                assert_eq!(body["version"], "1.0");
                server.seal(json!({"need_update":true,"latest_version":"2.0","latest_version_code":2,
                    "encrypted_info":crypto::encrypt(server.transport.as_ref().unwrap(), br#"{"update_verified":true}"#).unwrap()}))
            }
            "/api/v2/device/upload" => {
                assert_eq!(body["device_fingerprint"], FINGERPRINT);
                assert_eq!(body["kami"], "card");
                server.nested("encrypted_result", json!({"success":true,"verified":true,"main_kami_id":7,"total_processed":1,"timestamp":1700000000}))
            }
            "/api/v2/device/kamis" => {
                assert_eq!(body["device_fingerprint"], FINGERPRINT);
                server.seal(json!({"status":"success","kamis":[{"kami":"card","kami_hash":"hash","remaining_hours":24.5,"expire_at":"tomorrow","last_used_at":"today"}]}))
            }
            "/api/v2/heartbeat" => {
                assert_eq!(body["kami_hash"], "hash");
                server.nested("encrypted_result", alive())
            }
            path => panic!("unexpected endpoint {path}"),
        };
        ok(response)
    });
    client.connect().unwrap();
    assert_eq!(client.activate("card").unwrap().kami_hash, "hash");
    assert_eq!(
        client.validate("hash").unwrap().real_remaining_seconds,
        Some(12)
    );
    assert_eq!(client.check("card").unwrap().status, "activated");
    assert_eq!(client.unbind("hash").unwrap().strategy.kind, "no_change");
    assert_eq!(client.announcements(None, None).unwrap()[0].title, "hello");
    assert_eq!(
        client.check_update(1, "1.0").unwrap().latest_version_code,
        Some(2)
    );
    assert_eq!(client.upload_device("card").unwrap().total_processed, 1);
    assert_eq!(client.device_kamis().unwrap()[0].kami, "card");
    let heartbeat = client.heartbeat("hash").unwrap();
    assert_eq!(heartbeat.kami_expires_at_ms, None);
    assert!(client.heartbeat_due().unwrap() <= Instant::now() + Duration::from_secs(5));
    worker.join().unwrap();
}

#[test]
fn unsigned_or_tampered_errors_cannot_invalidate_the_session() {
    for case in 0..3 {
        let (mut client, worker) = mock(2, move |index, request, server| {
            if index == 0 {
                return ok(server.handshake(request));
            }
            server.request(request);
            let mut response = server.sign(json!({"code":1004,"message":"expired"}));
            match case {
                0 => {
                    response.as_object_mut().unwrap().remove("signature");
                }
                1 => response["signature"] = json!("00".repeat(64)),
                _ => response["message"] = json!("modified after signing"),
            }
            ok(response)
        });
        client.connect().unwrap();
        assert!(client.validate("hash").is_err());
        assert!(client.session.is_some());
        worker.join().unwrap();
    }
}

#[test]
fn signed_expiry_invalidates_the_session() {
    let (mut client, worker) = mock(2, |index, request, server| {
        if index == 0 {
            ok(server.handshake(request))
        } else {
            server.request(request);
            ok(server.sign(json!({"code":1004,"message":"expired"})))
        }
    });
    client.connect().unwrap();
    assert!(matches!(
        client.validate("hash"),
        Err(Error::Server { code: 1004, .. })
    ));
    assert!(client.session.is_none());
    worker.join().unwrap();
}

#[test]
fn nested_business_rejections_are_errors() {
    for result in [
        json!({"valid":false,"error":"kami_expired"}),
        json!({"valid":true,"verified":false}),
        json!({"valid":true}),
    ] {
        let (mut client, worker) = mock(2, move |index, request, server| {
            if index == 0 {
                ok(server.handshake(request))
            } else {
                server.request(request);
                ok(server.nested("encrypted_result", result.clone()))
            }
        });
        client.connect().unwrap();
        assert!(client.validate("hash").is_err());
        worker.join().unwrap();
    }
}

#[test]
fn malformed_inner_ciphertext_is_not_a_success() {
    let (mut client, worker) = mock(2, |index, request, server| {
        if index == 0 {
            ok(server.handshake(request))
        } else {
            server.request(request);
            ok(server.seal(json!({"status":"success","encrypted_result":"00"})))
        }
    });
    client.connect().unwrap();
    assert!(client.validate("hash").is_err());
    worker.join().unwrap();
}

#[test]
fn terminal_heartbeats_disconnect_and_disabled_only_stops_scheduling() {
    for status in [
        "kicked",
        "expired",
        "kami_expired",
        "kami_banned",
        "kami_not_found",
        "disabled",
        "future_status",
    ] {
        let (mut client, worker) = mock(2, move |index, request, server| {
            if index == 0 {
                return ok(server.handshake(request));
            }
            server.request(request);
            let mut result = alive();
            result["status"] = json!(status);
            result["session_expires_at_ms"] = Value::Null;
            ok(server.nested("encrypted_result", result))
        });
        client.connect().unwrap();
        assert_eq!(client.heartbeat("hash").unwrap().status, status);
        assert_eq!(client.session.is_some(), status == "disabled");
        assert_eq!(client.heartbeat_due(), None);
        worker.join().unwrap();
    }
}

#[test]
fn transient_heartbeat_failure_preserves_session_and_requests_prompt_retry() {
    let (mut client, worker) = mock(2, |index, request, server| {
        if index == 0 {
            ok(server.handshake(request))
        } else {
            server.request(request);
            (503, json!({}))
        }
    });
    client.connect().unwrap();
    assert!(matches!(client.heartbeat("hash"), Err(Error::Http(503))));
    assert!(client.session_remaining().unwrap() > Duration::from_secs(90));
    assert!(client.heartbeat_due().unwrap() <= Instant::now());
    worker.join().unwrap();
}

#[test]
fn expired_sessions_do_not_implicitly_reconnect() {
    let (mut client, worker) = mock(1, |_, request, server| ok(server.handshake(request)));
    client.connect().unwrap();
    client.session.as_mut().unwrap().expires = Instant::now() - Duration::from_secs(1);
    assert!(matches!(
        client.heartbeat("hash"),
        Err(Error::SessionExpired)
    ));
    assert_eq!(client.heartbeat_due(), None);
    worker.join().unwrap();
}

#[test]
fn heartbeat_response_can_renew_a_session_that_expired_in_flight() {
    let (mut client, worker) = mock(2, |index, request, server| {
        if index == 0 {
            return ok(server.handshake(request));
        }
        server.request(request);
        thread::sleep(Duration::from_millis(1100));
        ok(server.nested("encrypted_result", alive()))
    });
    client.connect().unwrap();
    client.session.as_mut().unwrap().expires = Instant::now() + Duration::from_secs(1);
    assert_eq!(client.heartbeat("hash").unwrap().status, "alive");
    assert!(client.session_remaining().unwrap() > Duration::from_secs(90));
    worker.join().unwrap();
}

#[test]
fn impossible_heartbeat_schedule_is_rejected_without_extending_the_lease() {
    let (mut client, worker) = mock(2, |index, request, server| {
        if index == 0 {
            return ok(server.handshake(request));
        }
        server.request(request);
        let mut result = alive();
        result["heartbeat_interval_sec"] = json!(100);
        ok(server.nested("encrypted_result", result))
    });
    client.connect().unwrap();
    let original = client.session.as_ref().unwrap().expires;
    assert!(client.heartbeat("hash").is_err());
    assert_eq!(client.session.as_ref().unwrap().expires, original);
    worker.join().unwrap();
}

#[test]
fn response_body_limit_is_enforced() {
    let (mut client, worker) = mock(1, |_, _, _| {
        ok(json!({"oversized":"x".repeat(2 * 1024 * 1024)}))
    });
    assert!(matches!(client.connect(), Err(Error::Transport(_))));
    assert!(client.session.is_none());
    worker.join().unwrap();
}
