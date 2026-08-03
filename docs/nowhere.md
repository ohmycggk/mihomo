# Nowhere 出站

`mihomo` 内置 Nowhere 出站（`type: nowhere`）。协议核心为共享库 `github.com/ohmycggk/nowhere-go`（Nowhere 1.5.x）；本仓只含客户端出站，**无 inbound**。服务端可对接 `sing-box` inbound 或 Rust 实现的 Nowhere Portal。

客户端可独立选择上行 / 下行外层载体（TLS/TCP 或 QUIC/UDP），覆盖完整 `up` × `down` 四矩阵；对称矩阵走直通快路径，非对称矩阵由 Portal 按 `(session_id, flow_id)` 配对。

## 最小配置

```yaml
proxies:
  - name: "nw"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
```

省略载体字段时默认 `up: udp` + `down: udp`（QUIC）。`password` 为必填字段，省略时启动报错。

## 上行 / 下行载体矩阵

| `up` | `down` | TCP 流量 | UDP 流量 |
| --- | --- | --- | --- |
| `udp` | `udp` | FLOW `DUPLEX` + QUIC 双向流 | FLOW `DUPLEX` + NOWU QUIC DATAGRAM（按当前 PMTU 分片） |
| `tcp` | `tcp` | FLOW `DUPLEX` + TLS/TCP | FLOW `DUPLEX` + typed UoT（TLS/TCP） |
| `tcp` | `udp` | FLOW `OPEN`/`ATTACH`：TLS/TCP 上行 + QUIC 流下行 | typed UoT 上行 + NOWU DATAGRAM 下行 |
| `udp` | `tcp` | FLOW `OPEN`/`ATTACH`：QUIC 流上行 + TLS/TCP 下行 | NOWU DATAGRAM 上行 + typed UoT 下行 |

- **所有 1.5 flow 都有 FLOW envelope**：对称矩阵使用 `DUPLEX`；非对称矩阵使用同一 `(session_id, flow_id)` 的 `OPEN` / `ATTACH`。
- **非对称**（`up != down`）：对端须监听 mix（sing-box `network: ["tcp","udp"]`，或 Portal `net=mix`）；配对不依赖源 IP。

载体字段规则：`up` / `down` 必须成对出现或同时缺省；只设其一启动报错。取值只能是 `tcp` 或 `udp`，其它值启动报错；同时缺省时默认 `udp` / `udp`。

## 字段说明

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `type` | — | 固定 `nowhere` |
| `name` | — | 出站名 |
| `server` | — | Portal 地址 |
| `port` | — | Portal 端口（mix 时 TCP/UDP 同端口；须大于 0） |
| `password` | — | 共享密钥（与 trojan/anytls/tuic 一致）；省略时启动报错 `missing password` |
| `up` / `down` | `udp` | 载体：`tcp` 或 `udp`；成对出现 |
| `dialer-proxy` | — | 链式代理：通过指定前置出站建立连接 |
| `pool` | `5`（tcp/tcp）/ `0` | warm TLS/TCP 连接数，仅 tcp/tcp 生效；配置文件取值 `0..256`，超出报 `invalid pool ... (maximum 256)`；显式 `0` 关闭预热但不限制业务 fresh；含 UDP 的矩阵忽略非零值并告警 |
| `prewarm-on-start` | `false` | 启动时即预热填充 TLS/TCP warm pool（仅 tcp/tcp）；默认保持「首业务拨号成功后再补池」行为 |
| `max-concurrent-dials` | `16` | 每 outbound 同时进行的物理 TLS/TCP 建连上限；省略或 `0` 用共享核心默认值 16 |
| `warm-backoff-initial` | `1`（秒） | warm prepare 失败后首次退避；省略或 `0` 用默认 |
| `warm-backoff-max` | `30`（秒） | warm prepare 退避上限；不得小于 initial |
| `alpn` | `now/1` | ALPN，**必须且只能提供一个值**：省略用默认 `now/1`；提供 0 个或多个值、空串、超长（>255 字节）都会报错 |
| `sni` | `server` | TLS/QUIC SNI |
| `skip-cert-verify` | `false` | 跳过证书校验（自签常用） |
| `fingerprint` | — | 证书 SHA-256 指纹 |
| `pin` | — | Nowhere 叶证书 SHA-256（64 位小写 hex）；设置后覆盖 SNI/证书链校验，TCP 与 QUIC 载体都生效；与 `fingerprint` 同时设置且不一致时 pin 优先并告警（同值同设不告警） |
| `certificate` / `private-key` | — | mTLS 客户端证书 |
| `client-fingerprint` | — | uTLS 指纹（仅 TLS/TCP 载体；QUIC 使用标准 TLS ClientHello，设置了会告警） |
| `ech-opts` | — | ECH（`enable`、`config`），TCP 与 QUIC 载体均生效 |
| `congestion-controller` | `bbr` | QUIC 拥塞控制 |
| `cwnd` | `32` | 拥塞窗口初值 |
| `udp` | `true` | 是否处理 UDP |

### TCP 连接池与风暴抑制

仅 `tcp` / `tcp` 使用 warm pool。语义：

- 池内只保存「已认证、尚未发 request」的连接；发 request 后 carrier 被消耗，不回池。
- 每个用户 TCP/UoT flow ≈ 一条独立 TLS/TCP carrier（固有线性成本）。
- `pool: 0` 关闭预热，但业务流量仍可并行 fresh dial。
- 冷池 miss：**先**完成业务 fresh，**成功后**才补 warm，避免 Portal 不可达时 fresh+warm 双倍拨号；`prewarm-on-start: true` 改为出站启动时即开始填池。
- warm prepare 失败进入指数退避（默认 1s→30s）；退避窗口内跳过补池。
- `warm-backoff-initial > warm-backoff-max` 或负数值会在启动时报错。
- `max-concurrent-dials` 同时约束业务 fresh 与 warm；warm 只非阻塞占用空闲 slot。

## 常见模式

### QUIC：udp/udp（推荐）

```yaml
proxies:
  - name: "nw-quic"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    up: udp
    down: udp
    congestion-controller: bbr
```

### TLS/TCP：tcp/tcp

```yaml
proxies:
  - name: "nw-tcp"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    up: tcp
    down: tcp
    pool: 5
    # 可选；省略即用默认值
    # prewarm-on-start: false
    # max-concurrent-dials: 16
    # warm-backoff-initial: 1
    # warm-backoff-max: 30
    skip-cert-verify: true
```

显式 `pool: 0` 关闭预热，每条 flow 新开连接；排查并发异常时可用它与 `pool: 5` 对照。

生产环境建议用 `pin` 锁定 Portal 叶证书而不是 `skip-cert-verify`：

```yaml
proxies:
  - name: "nw-tcp-pin"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    up: tcp
    down: tcp
    pin: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

### 非对称：tcp/udp、udp/tcp

```yaml
proxies:
  - name: "nw-tcp-udp"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    up: tcp
    down: udp
```

对端必须 mix。含 UDP 的矩阵不使用 warm pool；若配置了非零 `pool` 会被忽略并打警告。

### ECH

```yaml
proxies:
  - name: "nw-ech"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    ech-opts:
      enable: true
      config: "AEBl...="
```

### 自定义 TLS ALPN

```yaml
proxies:
  - name: "nw-custom"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    alpn: [h3]
```

`alpn` 必须且只能含一个值；`alpn: []`、多个值或空串都会启动报错。

### 链式代理

```yaml
proxies:
  - name: "nw-chained"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    dialer-proxy: "前置代理"
```

## share-link 导入

```
nowhere://<key>@host:port?up=tcp|udp&down=tcp|udp&sni=...&alpn=h3&pool=0..9&insecure=0|1&fp=<sha256>&pin=<sha256>&ech=<base64>#name
```

- URL username 为共享 key，导入为 `password`；**带 password 段的链接会被丢弃**。
- 省略端口时导入为 `port: 443`；导入结果固定带 `udp: true`。
- `up` / `down` 必须同时出现或同时缺省；单边设置拒绝导入，都省略时默认 udp/udp。载体只能是 `tcp` 或 `udp`。
- `alpn` 出现时必须恰好一个值，且非空、不超过 255 字节、不含逗号，否则整条链接拒绝。
- `pool` 仅在 tcp/tcp 矩阵导入，且钳制到 `0..9`（超过 9 告警并按 9 处理）；含 UDP 的矩阵忽略非零 pool 并告警。
- `insecure=1` → `skip-cert-verify: true`；`fp=` → `fingerprint`。
- `pin=none` 或空值忽略，其它值写入 `pin` 字段。
- `ech=` → `ech-opts: {enable: true, config: <value>}`。
- 风暴抑制字段（`max-concurrent-dials`、`warm-backoff-*`、`prewarm-on-start`）目前仅配置文件支持，不经 share-link 导入。

## 兼容性

- **Nowhere 1.5 必须锁步升级 Portal 与全部客户端。** 认证绑定真实 TLS exporter；混跑旧数据面不可用。
- 对称矩阵可对接任意单载体或 mix 入站；非对称必须 mix。
- 本仓 mihomo **无 inbound**；服务端用 sing-box inbound 或 Rust Portal。
- UoT：当 `up` 或 `down` 为 `tcp` 时支持（`SupportUOT()`）。
- 旧配置省略新字段时自动启用安全默认值；负数或 `warm-backoff-initial > warm-backoff-max` 会在启动时失败。
