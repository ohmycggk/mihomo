# Nowhere

`mihomo` 内置 Nowhere 出站与入站（`type: nowhere`）。协议核心为共享库 [`github.com/ohmycggk/nowhere-go`](https://github.com/ohmycggk/nowhere-go) **v1.8.3**（对齐 Rust Nowhere v1.8.3）。服务端也可对接 `sing-box` inbound 或 Rust Portal。

客户端可独立选择上行 / 下行外层载体：`tcp`（TLS/TCP）、`udp`（QUIC/UDP）或 `mix`（1.8.3 客户端策略，写入 FlowHeader 之前按 flow 解析）。对称矩阵走直通快路径，非对称矩阵由 Portal 按 `(session_id, flow_id)` 配对。`mix` 不会出现在线协议里。

## 协议版本

| 版本 | 要点 |
| --- | --- |
| **1.5** | 新线协议：认证绑定真实 TLS exporter；必须锁步升级 Portal 与客户端。1.4 数据面不可用。 |
| **1.6** | 线协议与 1.5 相同。 |
| **1.7** | FLOW 高 3 位为 HOPS；原生 Portal 链式转发（`next`）。直连客户端发 HOPS=0，仍可对接 1.5/1.6 Portal。链上每个 Portal 须 ≥ 1.7。 |
| **1.8** | TLS Mux：AuthFrame 后 `0xff` 进入 Mux 分片，其它字节为专用 FlowHeader。`mux=0` 专用通道客户端仍可对接 1.8 Portal。 |
| **1.8.3** | 客户端 `mix` 策略（`up`/`down` = `tcp` \| `udp` \| `mix`）。数据面与 1.8.2 相同；FlowHeader 仍只携带 TT / TQ / QT / QQ。`udp/udp&mux=1` 规范为 `mux=0`。 |

## 最小配置

```yaml
proxies:
  - name: "nw"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
```

省略载体字段时默认 `up: udp` + `down: udp`（QUIC）。`password` 为必填字段，省略时启动报错。入站始终同时监听 TCP 与 UDP（同端口 mix）。

## 上行 / 下行载体矩阵

`up` / `down` 必须成对出现或同时缺省；只设其一启动报错。取值只能是 `tcp`、`udp` 或 `mix`。

| `up` | `down` | TCP 流量 | UDP 流量 |
| --- | --- | --- | --- |
| `udp` | `udp` | FLOW `DUPLEX` + QUIC 双向流 | FLOW `DUPLEX` + NOWU QUIC DATAGRAM（按当前 PMTU 分片） |
| `tcp` | `tcp` | FLOW `DUPLEX` + TLS/TCP | FLOW `DUPLEX` + typed UoT（TLS/TCP） |
| `tcp` | `udp` | FLOW `OPEN`/`ATTACH`：TLS/TCP 上行 + QUIC 流下行 | typed UoT 上行 + NOWU DATAGRAM 下行 |
| `udp` | `tcp` | FLOW `OPEN`/`ATTACH`：QUIC 流上行 + TLS/TCP 下行 | NOWU DATAGRAM 上行 + typed UoT 下行 |

- **固定矩阵的 FLOW envelope**：对称用 `DUPLEX`；非对称用同一 `(session_id, flow_id)` 的 `OPEN` / `ATTACH`。
- **非对称**（`up != down`）：对端须 mix（同时接受 TLS/TCP 与 QUIC/UDP）；配对不依赖源 IP。mihomo 入站默认即 mix。
- **UoT**：`up` 或 `down` 为 `tcp` 或 `mix` 时支持（`SupportUOT()`）。纯 `udp/udp` 不走 UoT。

### mix（1.8.3）

`mix` 是客户端路由策略，按 flow 在写入 FlowHeader 之前解析为固定载体对，Portal 只看到 TT / TQ / QT / QQ。

| 配置 | 可解析为 | 说明 |
| --- | --- | --- |
| `mix` / `mix` | `tcp/tcp` 或 `udp/udp` | **不会**解析为非对称 TQ / QT |
| `tcp` / `mix` | `tcp/tcp` 或 `tcp/udp` | 下行在 TLS 与 QUIC 间选择 |
| `mix` / `tcp` | `tcp/tcp` 或 `udp/tcp` | 上行在 TLS 与 QUIC 间选择 |
| `udp` / `mix` | `udp/tcp` 或 `udp/udp` | |
| `mix` / `udp` | `tcp/udp` 或 `udp/udp` | |

主路由有准备预算（默认 1s，见 `mix-fallback-timeout`），超时后用**新 flow ID** 尝试另一条允许的载体对。一旦开始写 FlowHeader 或 Target 即提交该 flow；READY / 载荷失败**不会**回退。含 `mix` 的配置需要 TCP 与 QUIC 两套载体，对端须 mix。

## 字段说明

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `type` | — | 固定 `nowhere` |
| `name` | — | 出站名 |
| `server` | — | Portal 地址 |
| `port` | — | Portal 端口（mix 时 TCP/UDP 同端口；须大于 0） |
| `password` | — | 共享密钥（与 trojan/anytls/tuic 一致）；省略时启动报错 `missing password` |
| `up` / `down` | `udp` | 载体：`tcp`、`udp` 或 `mix`；成对出现 |
| `mux` | `0` | TLS 通道成帧：`0` 专用通道，`1` Mux 分片。任一方向为 `tcp` 或 `mix` 时生效；`udp/udp&mux=1` 规范为 `0`。非法值启动报错 |
| `mix-fallback-timeout` | `1`（秒） | mix 主路由准备超时；省略或 `0` 用 1s；负数启动报错 |
| `dialer-proxy` | — | 链式代理：通过指定前置出站建立连接 |
| `pool` | `5`（专用 tcp/tcp）/ `0` | warm TLS/TCP 连接数，**仅 `mux=0` 的 tcp/tcp** 生效；省略用 5；显式 `0` 关闭预热但不限制业务 fresh；超过 256 告警并钳制为 256；负数在专用 tcp/tcp 下启动报错。`mux=1` 或可走到 QUIC/`mix` 的矩阵忽略非零值并告警 |
| `prewarm-on-start` | `false` | 启动时即预热填充 TLS/TCP warm pool（仅专用 tcp/tcp）；默认保持「首业务拨号成功后再补池」 |
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
| `udp` | `true` | 是否处理 UDP；配置文件省略该键时默认为 `true` |

### TLS Mux（`mux=1`）

AuthFrame 之后，客户端写入 `0xff` 进入 Mux 分片（STREAM / WINDOW / DATAGRAM）；Portal 在同一 TLS 监听上自动识别专用通道与 Mux，无需入站配置。QUIC 从不使用 TLS Mux 帧。

- 分片按方向懒打开：每个分片最多 4 条活动 flow，空闲 30s 关闭。
- Mux **不**使用 dedicated warm pool；配置非零 `pool` 会被忽略并告警。
- `udp/udp` 无法启用 Mux，显式 `mux: 1` 会规范为 `0` 并告警。

### TCP 连接池与风暴抑制

仅 **`mux=0` 的 `tcp` / `tcp`** 使用 warm pool。语义：

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

### TLS/TCP：tcp/tcp（专用通道）

```yaml
proxies:
  - name: "nw-tcp"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    up: tcp
    down: tcp
    mux: 0
    pool: 5
    # 可选；省略即用默认值
    # prewarm-on-start: false
    # max-concurrent-dials: 16
    # warm-backoff-initial: 1
    # warm-backoff-max: 30
    skip-cert-verify: true
```

显式 `pool: 0` 关闭预热，每条 flow 新开连接；排查并发异常时可用它与 `pool: 5` 对照。

### TLS Mux：tcp/tcp + mux=1

```yaml
proxies:
  - name: "nw-mux"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    up: tcp
    down: tcp
    mux: 1
```

多条逻辑流共享标记过的 TLS 分片。对端 Portal 自动识别，无需改入站配置。

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

### mix（按 flow 选择载体）

```yaml
proxies:
  - name: "nw-mix"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    up: mix
    down: mix
    mux: 1
    # mix-fallback-timeout: 1
```

`mix/mix` 每个 flow 解析为 `tcp/tcp` 或 `udp/udp`。对端必须 mix。含 `mix` 或 UDP 的矩阵不使用 warm pool；若配置了非零 `pool` 会被忽略并打警告。

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

对端必须 mix。

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

## 入站（Portal）

入站同时监听 TLS/TCP 与 QUIC/UDP（同端口），认证后把 TCP/UDP 交给隧道。省略证书时生成内存自签证书，客户端需 `skip-cert-verify` 或 `pin`。AuthFrame 后自动识别专用通道与 Mux，入站无需 `mux` 字段。

```yaml
listeners:
  - name: nowhere-in-1
    type: nowhere
    port: 10825
    listen: 0.0.0.0
    password: PASSWORD
    # certificate / private-key 成对出现；都省略则用内存自签证书
    # alpn: [now/1]
    # congestion-controller: bbr
    # cwnd: 32
```

### Portal 链式转发（`next`，1.7+）

填写 `next` 后，本节点作为中继把**全部**入站 flow 转发给下一个 Nowhere Portal，绕过 mihomo 路由 / `rule` / `proxy`，无回退。`next` 可使用 `mux` 与 `mix`。

```yaml
listeners:
  - name: nw-relay
    type: nowhere
    port: 10826
    password: relay-key
    next:
      server: origin.example
      port: 2080
      password: origin-key
      up: tcp
      down: tcp
      mux: 0
      pool: 5
      # mix-fallback-timeout: 1
      sni: origin.example
      pin: <leaf cert sha256 hex>
```

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `next.server` / `port` / `password` | — | 下一跳地址、端口（1–65535）、共享密钥（必填） |
| `next.up` / `down` | `udp` / `udp` | 通往下一跳的载体：`tcp`、`udp` 或 `mix`；须成对 |
| `next.mux` | `0` | `0` 专用 TLS，`1` Mux；`udp/udp` 规范为 `0` |
| `next.pool` | `5`（专用 tcp/tcp） | 仅 `mux=0` 的 tcp/tcp 生效；超过 256 钳制 |
| `next.mix-fallback-timeout` | `1`（秒） | mix 主路由准备超时 |
| `next.sni` | — | 省略 / 空 / `none` 关闭证书链与域名校验（域名形式的 `server` 仍可作为 ClientHello SNI）；显式 DNS 名启用系统根证书校验 |
| `next.pin` | — | 叶证书 SHA-256；非空且非 `none` 时优先于 `sni` |

跳数预算：链上第一个转发 Portal 将 HOPS 初始化为 7，每跳减 1；HOPS=1 仍要继续转发时以 `FLOW_LIMIT` 拒绝。链上每个 Portal 须 ≥ 1.7。转发连接的 ALPN 与 QUIC 拥塞参数继承自该监听器。

## share-link 导入

```
nowhere://<key>@host:port?up=tcp|udp|mix&down=tcp|udp|mix&mux=0|1&sni=...&alpn=h3&pool=0..256&insecure=0|1&fp=<sha256>&pin=<sha256>&ech=<base64>#name
```

- URL username 为共享 key，导入为 `password`；**带 password 段的链接会被丢弃**。
- 省略端口时导入为 `port: 443`；导入结果固定带 `udp: true`。
- `up` / `down` 必须同时出现或同时缺省；单边设置拒绝导入，都省略时默认 udp/udp。载体只能是 `tcp`、`udp` 或 `mix`。
- `mux=1` 写入配置；`udp/udp&mux=1` 规范为 0 且不写出 `mux`。非法 `mux` 拒绝导入。
- `alpn` 出现时必须恰好一个值，且非空、不超过 255 字节、不含逗号，否则整条链接拒绝。
- `pool` 仅在专用（`mux=0`）tcp/tcp 矩阵导入，超过 256 告警并钳制为 256；含 UDP/`mix` 或 `mux=1` 时忽略非零 pool 并告警。
- `insecure=1` → `skip-cert-verify: true`；`fp=` → `fingerprint`。
- `pin=none` 或空值忽略，其它值写入 `pin` 字段。
- `ech=` → `ech-opts: {enable: true, config: <value>}`。
- 旧别名 `net=` / `spec=` / `key=` 不再识别。
- `mix-fallback-timeout`、风暴抑制字段（`max-concurrent-dials`、`warm-backoff-*`、`prewarm-on-start`）目前仅配置文件支持，不经 share-link 导入。

## 兼容性

- **1.5 认证必须锁步**：混跑旧数据面不可用。1.5–1.7 直连的认证、Target、UoT、DATAGRAM 格式相同。
- **1.8 Mux**：`mux=0` 专用客户端可对接 1.8 Portal；Portal 自动识别两种 TLS 成帧。
- **1.8.3 mix** 只存在于客户端；线协议仍是四矩阵。对端 mix 入站即可。
- 对称矩阵可对接任意单载体或 mix 入站；非对称与 `mix` 必须 mix。
- 直连出站发送 HOPS=0，可对接 1.5/1.6 Portal；原生 `next` 链要求全部 Portal ≥ 1.7。
- 本仓 mihomo 同时提供出站与入站。
- 旧配置省略新字段时自动启用安全默认值（`udp/udp`、`mux=0`、专用 tcp/tcp 的 `pool=5`）；负数或 `warm-backoff-initial > warm-backoff-max` 会在启动时失败。
