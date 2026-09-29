# thomeauth

ThomeAuth 的有状态 Rust 客户端。一个 Client 管理一组应用配置、设备指纹、
会话密钥与过期时间，提供阻塞式 HTTP 接口。

## 安装

```toml
[dependencies]
thomeauth = { git = "https://github.com/psyche314/thomeauth" }
```

## 使用

```rust
use thomeauth::{Activation, Client, Config};

fn activate(
    config: Config,
    fingerprint: &str,
    card: &str,
) -> thomeauth::Result<(Client, Activation)> {
    let mut client = Client::new(config, fingerprint)?;
    client.connect()?;
    let activation = client.activate(card)?;
    client.validate(&activation.kami_hash)?;
    Ok((client, activation))
}
```

Config 的四个字段均由应用开发者提供：app_id、api_key、x25519_public_key、
ed25519_public_key。两个公钥使用原始的 32 字节数组；设备指纹按调用方传入的
字符串发送，客户端不采集平台标识，也不自行哈希或改变它。

Client::new 不发起网络请求；connect 显式建立或替换会话。Client::with_http
允许传入自定义服务地址和 ureq::Agent，以配置代理、超时或测试服务。
默认 HTTP 超时为 15 秒，不跟随重定向，单个响应最多读取 2 MiB。
自定义 Agent 应保持禁止跨来源重定向。

## 接口

| 方法 | 协议端点 | 返回值 |
| --- | --- | --- |
| connect | /session | 建立会话 |
| activate | /activate | Activation |
| validate | /use | Validation |
| check | /check | CardStatus |
| unbind | /unbind | Unbind |
| announcements | /announcements | `Vec<Announcement>` |
| check_update | /update/check | Update |
| upload_device | /device/upload | DeviceUpload |
| device_kamis | /device/kamis | `Vec<DeviceCard>` |
| heartbeat | /heartbeat | Heartbeat |

响应字段保留协议命名。客户端验证外层签名和内层加密结果，不把外层混淆字段
当作授权结果。卡密拒绝返回 Error::Rejected；已验签的非零响应码返回
Error::Server。网络错误、签名错误和格式错误分别返回对应错误类型。

## 会话与心跳

- 会话有效期由服务端时间差计算，使用单调时钟计时，并扣除请求耗时。
- heartbeat 发送一次心跳；成功后更新会话期限和 heartbeat_due 返回的下次时间。
- 心跳网络失败保留尚未过期的会话，下次时间设为立即重试。退避策略由调用方决定。
- 被顶号、过期、封禁以及未知的终止状态会清除会话；disabled 只停止心跳调度。
- 会话过期后必须显式 connect；请求不会自动重试或自动重新登录。
- disconnect 仅清理本地会话，不解绑远端设备。解绑必须显式调用 unbind。

所有网络方法都会阻塞。应用自行选择工作线程、心跳调度、持久化及 UI。
卡密哈希可用于后续验证，应当按凭据保存。含凭据的配置和响应类型不实现 Debug。

协议请求时间戳为毫秒，普通响应时间戳为秒；心跳字段以 _ms 或 _sec 标明单位。
永久卡的可空到期字段保留 None，不将其替换为零或当前时间。

## 验证

```sh
cargo test --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

测试使用本地模拟服务覆盖协议端点、验签和解密失败、会话证明、到期、心跳续期及
终止状态，并使用 RFC 向量和独立实现生成的密码学向量。测试不连接真实授权账号，
不证明特定应用后台配置已通过联调。

协议来源：[官方 API 文档](https://www.thomelua.com/api_document)。

## 许可

MIT OR Apache-2.0，由使用者任选其一。
