# Nowhere

`mihomo` 内置 Nowhere 出站与入站（`type: nowhere`）。协议核心内联于 `transport/nowhere/core`，对齐 Rust Nowhere **2.2.1**（`UPSTREAM.lock` commit `00006969`）。服务端也可对接 `sing-box` inbound 或 Rust Portal，对端必须同样运行 Nowhere 2。

Nowhere 2 的唯一 ALPN 是 `nw2`。认证盐、Mux 帧与 QUIC UDP 头均已更换，**不能**与 1.8 `now/1` 对端完成握手。

客户端可独立选择上行 / 下行外层载体：`tcp`（TLS/TCP）或 `udp`（QUIC/UDP）。对称矩阵走直通快路径，非对称矩阵由 Portal 按 `(session_id, flow_id)` 配对。

## 协议版本

| 版本 | 要点 |
| --- | --- |
| **1.5** | 新线协议：认证绑定真实 TLS exporter；必须锁步升级 Portal 与客户端。1.4 数据面不可用。 |
| **1.6** | 线协议与 1.5 相同。 |
| **1.7** | FLOW 高 3 位为 HOPS；原生 Portal 链式转发（`next`）。直连客户端发 HOPS=0。 |
| **1.8** | TLS Mux：AuthFrame 后 `0xff` 进入 Mux 分片。`mux=0` 专用通道客户端仍可对接 1.8 Portal。 |
| **1.8.3** | 历史：客户端 `mix` 策略（`up`/`down` = `tcp` \| `udp` \| `mix`）。数据面与 1.8.2 相同。Nowhere 2.2 起不再接受 `mix`。 |
| **2.0** | ALPN 固定 `nw2`；AuthFrame 盐改为 `nowhere/nw2/auth-root`；Mux 改为 7 字节 OPEN/DATA/WINDOW/FIN/RESET；QUIC UDP 头压缩；flow ID 为 30 位（`1..=0x3fffffff`）。可选 Morph（`morph=1`）在 TLS/QUIC 之下做 keyed transform。与 1.8 不互通。 |
| **2.2.1** | 去掉 `mix` 载波与 fallback。Portal 共享密钥为 URL 解码后 32–64 位小写十六进制。Morph 的 TCP prelude 为 64 字节，默认 `full8`，与 2.0.x Morph 线级不兼容。出站与 `next` 支持 `dial4` / `dial6` 源地址绑定。 |

## 最小配置

```yaml
proxies:
  - name: "nw"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
```

省略载体字段时默认 `up: udp` + `down: udp`（QUIC）。省略 `alpn` 时使用协议默认 `nw2`。`password` 为必填字段，省略时启动报错。上面是出站示例，客户端密钥保持宽松（1–255 字节）。入站始终同时监听 TCP 与 UDP（同端口）。

## 上行 / 下行载体矩阵

`up` / `down` 必须成对出现或同时缺省；只设其一启动报错。取值只能是 `tcp` 或 `udp`。

| `up` | `down` | TCP 流量 | UDP 流量 |
| --- | --- | --- | --- |
| `udp` | `udp` | FLOW `DUPLEX` + QUIC 双向流 | FLOW `DUPLEX` + NOWU QUIC DATAGRAM（按当前 PMTU 分片） |
| `tcp` | `tcp` | FLOW `DUPLEX` + TLS/TCP | FLOW `DUPLEX` + typed UoT（TLS/TCP） |
| `tcp` | `udp` | FLOW `OPEN`/`ATTACH`：TLS/TCP 上行 + QUIC 流下行 | typed UoT 上行 + NOWU DATAGRAM 下行 |
| `udp` | `tcp` | FLOW `OPEN`/`ATTACH`：QUIC 流上行 + TLS/TCP 下行 | NOWU DATAGRAM 上行 + typed UoT 下行 |

- **固定矩阵的 FLOW envelope**：对称用 `DUPLEX`；非对称用同一 `(session_id, flow_id)` 的 `OPEN` / `ATTACH`。
- **非对称**（`up != down`）：对端须同时接受 TLS/TCP 与 QUIC/UDP；配对不依赖源 IP。mihomo 入站默认同时监听两种载体。
- **UoT**：`up` 或 `down` 为 `tcp` 时支持（`SupportUOT()`）。纯 `udp/udp` 不走 UoT。

## 字段说明

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `type` | — | 固定 `nowhere` |
| `name` | — | 出站名 |
| `server` | — | Portal 地址 |
| `port` | — | Portal 端口（TCP 与 UDP 同端口；须大于 0） |
| `password` | — | 客户端共享密钥，1–255 字节；省略时启动报错 `missing password`。Portal 入站与 `next` 更严，见下方入站说明 |
| `up` / `down` | `udp` | 载体：`tcp` 或 `udp`；成对出现 |
| `mux` | `0` | TLS 通道成帧：`0` 专用通道，`1` Mux 分片。任一方向为 `tcp` 时生效；`udp/udp&mux=1` 规范为 `0`。非法值启动报错 |
| `dial4` / `dial6` | 自动 | 连接 Portal 时按地址族绑定源地址。`auto` 或空表示由内核选择；`dial4` 必须是 IPv4 字面量，`dial6` 必须是非 IPv4-mapped 的 IPv6 字面量。不经 share-link 导入 |
| `dialer-proxy` | — | 链式代理：通过指定前置出站建立连接 |
| `pool` | `5`（专用 tcp/tcp）/ `0` | warm TLS/TCP 连接数，**仅 `mux=0` 的 tcp/tcp** 生效；省略用 5；显式 `0` 关闭预热但不限制业务 fresh；超过 256 告警并钳制为 256；负数在专用 tcp/tcp 下启动报错。`mux=1` 或含 `udp` 的矩阵忽略非零值并告警 |
| `prewarm-on-start` | `false` | 启动时即预热填充 TLS/TCP warm pool（仅专用 tcp/tcp）；默认保持「首业务拨号成功后再补池」 |
| `max-concurrent-dials` | `16` | 每 outbound 同时进行的物理 TLS/TCP 建连上限；省略或 `0` 用共享核心默认值 16 |
| `warm-backoff-initial` | `1`（秒） | warm prepare 失败后首次退避；省略或 `0` 用默认 |
| `warm-backoff-max` | `30`（秒） | warm prepare 退避上限；不得小于 initial |
| `alpn` | `nw2` | ALPN，**必须且只能提供一个值**：省略用协议默认 `nw2`。官方 Rust Portal 只接受 `nw2`。提供 0 个或多个值、空串、超长（>255 字节）都会报错 |
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
| `morph` | `false` | 官方 CLI `morph=1`：在 TLS/QUIC 之下用本跳 `password` 做 keyed transform。YAML `true`/`1` 启用，省略/`false`/`0` 为裸 TLS/QUIC。协议不协商，对端必须同样开启 |

### Morph（`morph: true`）

对应官方 CLI 的 `morph=1`：在 TLS/QUIC 握手与载荷之下，用本跳共享密钥派生的 ChaCha20 密钥流做 XOR。协议不协商——两端必须同时开或同时关，否则无法完成握手。Nowhere 2.2.1 的 Morph 与 2.0.x Morph 线级不兼容，`morph=1` 的两端都必须运行 Nowhere 2.2.1。

- TLS/TCP：先发送 64 字节 prelude，再发送 12 字节 nonce，然后变换 TLS 字节流。prelude 默认 `full8`（每个字节 8 位都随机）。环境变量 `NOW_MORPH_TCP_PRELUDE=low7` 沿用旧策略（清除每个字节的高位）；设置为空串会被拒绝。跳的两端必须使用相同策略。
- QUIC/UDP：每个数据报带独立 12 字节 nonce，再变换 QUIC 报文。
- 密钥由本跳 `password` 派生（入站 `next` 则由 `next.password` 派生）。
- 与 `up` / `down` / `mux` 正交：四种固定矩阵均可启用。

### TLS Mux（`mux=1`）

AuthFrame 之后，客户端写入 `0xff` 进入 Mux 分片。Portal 在同一 TLS 监听上自动识别专用通道与 Mux，无需入站配置。QUIC 从不使用 TLS Mux 帧。

Nowhere 2 的 Mux 帧为 7 字节头：`OPEN` / `DATA` / `WINDOW` / `FIN` / `RESET`。WINDOW 与 OPEN 的窗口值以 1 KiB 为单位。默认窗口 16/32 MiB，单载体最多 4096 条活动流。

- 同一 session 最多 **8** 条全双工 Mux TLS 载体；新 flow 按占用率（发送/接收窗口与出站队列）选载体，不再按「每分片 4 条流」切分。
- 空闲 30s 的已认证 Mux 载体关闭。
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

多条逻辑流共享最多 8 条全双工 Mux TLS 载体。对端 Portal 自动识别，无需改入站配置。

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

对端必须同时接受 TLS/TCP 与 QUIC/UDP。含 `udp` 的矩阵不使用 warm pool；若配置了非零 `pool` 会被忽略并打警告。

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
    alpn: [nw2]
```

`alpn` 必须且只能含一个值；`alpn: []`、多个值或空串都会启动报错。官方 Rust Portal 只协商 `nw2`，自定义 ALPN 仅在两端 mihomo（或同等实现）一致时可用。

### Morph

```yaml
proxies:
  - name: "nw-morph"
    type: nowhere
    server: example.com
    port: 2077
    password: secret
    morph: true
```

服务端入站也必须 `morph: true`（或 `morph: 1`），并且两端都要运行 Nowhere 2.2.1。只开一端无法握手。

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

入站同时监听 TLS/TCP 与 QUIC/UDP（同端口），认证后把 TCP/UDP 交给隧道。省略证书时生成内存自签证书，客户端需 `skip-cert-verify` 或 `pin`。AuthFrame 后自动识别专用通道与 Mux，入站无需 `mux` 字段。`morph` 须与客户端一致。

Portal 共享密钥（监听器 `password` 与 `next.password`）在 URL 百分号解码后必须是 32–64 位小写十六进制（`[0-9a-f]`，允许奇数长度），文本直接作为密钥材料，不再做十六进制解码。客户端出站密钥仍为 1–255 字节，没有字符限制。

```yaml
listeners:
  - name: nowhere-in-1
    type: nowhere
    port: 10825
    listen: 0.0.0.0
    password: 0123456789abcdef0123456789abcdef
    # certificate / private-key 成对出现；都省略则用内存自签证书
    # alpn: [nw2]
    # congestion-controller: bbr
    # cwnd: 32
    # morph: true              # 官方 CLI morph=1；客户端必须同样开启，且两端都是 Nowhere 2.2.1
```

### Portal 链式转发（`next`，1.7+）

填写 `next` 后，本节点作为中继把**全部**入站 flow 转发给下一个 Nowhere Portal，绕过 mihomo 路由 / `rule` / `proxy`，无回退。`next` 可使用 `mux`。链上每个 Portal 必须是 Nowhere 2（ALPN `nw2`），与 1.8 不互通；`morph=1` 的每一跳还必须是 Nowhere 2.2.1。

```yaml
listeners:
  - name: nw-relay
    type: nowhere
    port: 10826
    password: 0123456789abcdef0123456789abcdef
    next:
      server: origin.example
      port: 2080
      password: 0123456789abcdef0123456789abcde0
      up: tcp
      down: tcp
      mux: 0
      pool: 5
      # dial4: auto          # IPv4 源地址，或 auto
      # dial6: auto          # IPv6 源地址，或 auto
      sni: origin.example
      pin: <leaf cert sha256 hex>
      # morph: true           # 省略则继承监听器 morph
```

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `next.server` / `port` / `password` | — | 下一跳地址、端口（1–65535）、共享密钥（必填）。密钥为 URL 解码后 32–64 位小写十六进制 |
| `next.up` / `down` | `udp` / `udp` | 通往下一跳的载体：`tcp` 或 `udp`；须成对 |
| `next.mux` | `0` | `0` 专用 TLS，`1` Mux；`udp/udp` 规范为 `0` |
| `next.pool` | `5`（专用 tcp/tcp） | 仅 `mux=0` 的 tcp/tcp 生效；超过 256 钳制 |
| `next.dial4` / `dial6` | 自动 | 连接下一跳时按地址族绑定源地址。规则与出站 `dial4` / `dial6` 相同 |
| `next.sni` | — | 省略 / 空 / `none` 关闭证书链与域名校验（域名形式的 `server` 仍可作为 ClientHello SNI）；显式 DNS 名启用系统根证书校验 |
| `next.pin` | — | 叶证书 SHA-256；非空且非 `none` 时优先于 `sni` |
| `next.morph` | 继承监听器 | 下一跳是否启用 Morph；省略时继承本监听器的 `morph`（与官方 `portal://...?morph=1&next=...` 一致）。密钥由 `next.password` 派生。启用时下一跳必须是 Nowhere 2.2.1 |

跳数预算：链上第一个转发 Portal 将 HOPS 初始化为 7，每跳减 1；HOPS=1 仍要继续转发时以 `FLOW_LIMIT` 拒绝。转发连接的 ALPN 与 QUIC 拥塞参数继承自该监听器。

## share-link 导入

```
nowhere://<key>@host:port?up=tcp|udp&down=tcp|udp&mux=0|1&morph=0|1&sni=...&alpn=nw2&pool=0..256&insecure=0|1&fp=<sha256>&pin=<sha256>&ech=<base64>#name
```

- URL username 为共享 key，导入为 `password`；**带 password 段的链接会被丢弃**。客户端密钥保持 1–255 字节，没有十六进制限制。
- 省略端口时导入为 `port: 443`；导入结果固定带 `udp: true`。
- `up` / `down` 必须同时出现或同时缺省；单边设置拒绝导入，都省略时默认 udp/udp。载体只能是 `tcp` 或 `udp`，`mix` 会被拒绝。
- `mux=1` 写入配置；`udp/udp&mux=1` 规范为 0 且不写出 `mux`。非法 `mux` 拒绝导入。
- `morph=1` 写入 `morph: true`；`morph=0` 或省略不写出该字段（默认裸 TLS/QUIC）。非法值拒绝导入。
- `alpn` 出现时必须恰好一个值，且非空、不超过 255 字节、不含逗号，否则整条链接拒绝。省略时出站使用协议默认 `nw2`。官方 Portal 只接受 `nw2`。
- `pool` 仅在专用（`mux=0`）tcp/tcp 矩阵导入，超过 256 告警并钳制为 256；含 UDP 或 `mux=1` 时忽略非零 pool 并告警。
- `insecure=1` → `skip-cert-verify: true`；`fp=` → `fingerprint`。
- `pin=none` 或空值忽略，其它值写入 `pin` 字段。
- `ech=` → `ech-opts: {enable: true, config: <value>}`。
- 旧别名 `net=` / `spec=` / `key=` 不再识别。
- `dial4` / `dial6` 与风暴抑制字段（`max-concurrent-dials`、`warm-backoff-*`、`prewarm-on-start`）目前仅配置文件支持，不经 share-link 导入。

## 兼容性

- **Nowhere 2 必须锁步**：ALPN `nw2`、AuthFrame 盐、Mux 帧与 QUIC UDP 头均与 1.8 不兼容。混跑 1.8 `now/1` 无法完成握手。
- **Mux**：`mux=0` 专用客户端可对接 Nowhere 2 Portal；Portal 自动识别两种 TLS 成帧。同一 session 最多 8 条 Mux TLS 载体。
- 对称矩阵可对接只开一种载体的 Portal；非对称必须对端同时接受 TLS/TCP 与 QUIC/UDP。
- 直连出站发送 HOPS=0；原生 `next` 链要求全部 Portal 都是 Nowhere 2（ALPN `nw2`），与 1.8 不互通。
- 本仓 mihomo 同时提供出站与入站。
- 旧配置省略新字段时自动启用安全默认值（`udp/udp`、`mux=0`、`alpn=nw2`、`morph=0`、专用 tcp/tcp 的 `pool=5`）；负数或 `warm-backoff-initial > warm-backoff-max` 会在启动时失败。`up`/`down` 为 `mix` 会在启动时失败。`mix-fallback-timeout` 已不再是配置字段。
- **Morph**：YAML `true`/`1` 与 share-link `morph=1` 启用；省略/`false`/`0` 为裸 TLS/QUIC。对端必须使用相同设置，协议不协商，且两端都要运行 Nowhere 2.2.1。入站 `next.morph` 省略时继承监听器。
