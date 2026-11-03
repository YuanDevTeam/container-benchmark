# 服务端选择合同

服务端由协议和所需的确切入站字段决定。只有固定版本的官方源码或文档明确证明前一实现缺少该能力，才选择下一顺位。除下文明确授权的 Mieru listener 缺陷例外外，握手、互通、准备或压力失败不构成切换理由；下载、构建和启动失败也不换实现。客户端对照固定为 Vole 和 Mihomo，复用原协议服务端；兼容问题独立记录，实际指标照常统计，遵循[验证策略](validation-strategy.md)。服务端顺位和例外保持。

| 协议 | 顺序 |
| --- | --- |
| VLESS | Mihomo → Xray-core → V2Ray-core |
| VMess | Mihomo → V2Ray-core |
| SS2022 | Mihomo → shadowsocks-rust → Xray-core |
| Trojan | Mihomo → Xray-core |
| TUIC v5 | 官方 Itsusinn/tuic；仅 UoT v2、服务端 mTLS 客户端证书认证专项使用 Mihomo |
| 其他 | Mihomo → 官方服务端 |

统一选择器 `src/container_benchmark/server_selection.py` 在主互通入口、单组与批量服务端的下载、配置和启动前验证顺位。压力结果的 `peer_selection` 记录实际协议服务端、顺序、前序字段缺口及源码依据、辅助前端。组合名称和 factory 的 `backend` 标签不覆盖这份决定。

TUIC `native`、`quic` 的服务端为 Itsusinn，后端标识为 `tuic`，运行产物为 `tuic-server`；UoT v2 与服务端 mTLS 客户端证书认证按下表字段缺口使用 Mihomo。每日解析官方最新稳定版，排除开发版和预发布版本，从共享缓存复制运行副本；单次会话冻结实际版本、源码与 ELF 身份，不在测试矩阵固定版本。历史 Mihomo、原项目官方端和辅助对照均保留原身份及 FAIL／ERROR，不自动改签为 Itsusinn 正式验收；选到 Itsusinn 的窗口须匹配该服务端证明，仍选 Mihomo 的 UoT v2 保持原通过记录规则。

## 已确认 Mieru listener 缺陷的例外

用户明确允许已确认 Mihomo listener 错误的 Mieru 场景使用官方服务器。五个既有压力组合显式选择官方 mita：TCP载体standard／no-wait／pattern，以及UDP载体standard／pattern；主互通九项仍使用Mihomo，不因一次失败自动扩大例外。

TCP载体的[跨逻辑UDP会话NAT错回](../conclusions/mieru-tcp-nat-alias.md)已有32条直接事件。UDP载体的[正常Close／在途DATA边界](../conclusions/mieru-sdk-close-current.md)已有双端证据；其中另8个约63秒timeout的先前停滞仍未知。先前稳定版官方mita也使用同源SDK和类似BidiCopy关闭；新会话解析最新稳定版，选官方端用于排除listener层差异，不预先宣称尾缺已修复。

例外作为内部 `peer_exception` 和结果 `peer_selection.exceptions` 记录，明确缺陷、来源、证据与授权；不把已支持字段伪报缺失，不加入Core YAML。未知例外、其他协议和未审查fixture不能绕过顺位。mita仍按每日最新稳定版从共享缓存复制，冻结本次实际ELF和配置身份；失败时所选参考客户端仍使用同一mita服务器。

当前官方mita窗口须匹配server=mieru的独立PASS及回归基线，不能跳过或改签旧Mihomo PASS。历史FAIL／ERROR及源码、服务端身份保留；官方端真实TUN前检、压力与Stop结果以实际运行报告为准，静态接入不代表通过。

## 允许进入后序的缺口

各字段的审计来源由统一选择器记录；以下缺口均依据对应官方源码。审计 revision 不固定运行版本，版本更新需重新核对字段能力，不根据某次测试结果推导“不支持”。下表 TUIC 的完整审计 revision 为 `fe0b7ec665762573b239d0ddf343620b7856ff52`。

| 所需入站能力 | 选择 | 前序缺口与来源 |
| --- | --- | --- |
| SS2022 多用户 EIH 身份密钥 | shadowsocks-rust | Mihomo 的 `listener/inbound/shadowsocks.go` 未提供相应 EIH 身份与用户密钥配置；普通单密钥 SS2022 仍用 Mihomo |
| VLESS 旧 H2 明文／TLS、WebSocket 自定义早数据头／路径 | V2Ray-core | Mihomo 的 `listener/inbound/vless.go` 不表达对应传输字段；Xray-core `7da5dae6` 的 `transport/internet` 已移除旧 H2，且不表达这两类自定义 WS 早数据输入 |
| VMess 旧 H2、自定义 WS 早数据头／路径 | V2Ray-core | Mihomo 的 `listener/inbound/vmess.go` 不表达对应入站字段 |
| VLESS／VMess raw TCP HTTP header 伪装 | Xray-core／V2Ray-core | Mihomo 对应 `listener/inbound/vless.go`／`vmess.go` 未提供 raw TCP HTTP header 配置 |
| VLESS XHTTP HTTP/3 入站 | Xray-core | Mihomo 的 `listener/sing_vless/server.go` 不接入 XHTTP H3 |
| Trojan UDP 中的域名地址编码 | Xray-core | Mihomo 的 `transport/trojan/trojan.go` 对该地址编码解码拒绝；使用实际 IP 地址的 TCP／WS／gRPC 基础组合仍用 Mihomo |
| HY2 多端口跳跃复用同一 QUIC 连接 | 官方 Hysteria2 | Mihomo 的 `listener/sing_hysteria2/server.go` 为各端口分别创建 service 和 `quic.Listen`，监听多个端口不等于同一 QUIC 连接跨端口迁移 |
| HY2 服务端 `disableUDP` | 官方 Hysteria2 | Mihomo 对应 listener 不提供该服务端字段 |
| TUIC Sing UoT v2 | Mihomo | Itsusinn 稳定版 `v1.8.11`／`fe0b7ec` 中 `tuic-server/src/connection/handle_task.rs` 的 `handle_connect` 直接解析目标并建立 TCP 转发，不处理 `sp.v2.udp-over-tcp.arpa`；Mihomo `listener/sing/sing.go` 明确识别 `uot.MagicAddress`。保持 Vole 原 UoT v2 wire，不将其替换为原生 TUIC UDP |
| TUIC 服务端 mTLS 客户端证书认证 | Mihomo | Itsusinn 稳定版 `v1.8.11`／`fe0b7ec` 的 `tuic-server/src/server.rs` 对 TLS 配置使用 `with_no_client_auth()`，未提供客户端 CA／验证器配置；该源码仅为字段缺口依据 |
| MASQUE、WireGuard 入站 | 对应官方协议路径 | Mihomo 的 `listener/inbound` 没有对应 listener；MASQUE 使用基于官方公共库的受控夹具，不宣称真实 WARP 服务 |

HY2 的官方补充目录仅保留两个跳跃组合和一个 `disableUDP` 组合。HY2 的 mTLS、Salamander 本身不是切到官方端的理由。TUIC 只有上表 UoT v2、客户端证书认证字段专项可用 Mihomo，普通握手、互通、准备、压力或启动失败均不切换。

## 协议服务端与辅助层

- `custom` 是配置 factory，实际协议服务端为 Mihomo。
- Caddy 的 XHTTP H3 mTLS 组合使用 Caddy 处理外层 H3 和客户端证书，协议处理层为 Xray-core。
- WebSocket 插件可使用官方 v2ray-plugin 前端，SS2022 解码器仍为 Mihomo；插件名称不改变 SS2022 服务端顺序。
- 分层 XHTTP H3 的 packetaddr／mux 见证包含独立解码层，需同时保留外层 Xray 与内层 Mihomo 的身份。
- TLS／HTTP 观察前端、STUN 和 Realm 注册设施分别见证握手或控制面，不作为更换代理协议服务端的理由。
- TCP ECH 的 Xray 命令仅生成合成密钥；公开 TLS／VLESS listener 仍为 Mihomo。DoH/H3 的独立 DNS 原站使用官方 dnsproxy：Mihomo `dns/server.go` 只启动 UDP／TCP DNS 服务，没有对应 H3 DNS listener。

## 当前目录与验证范围

目录为 **178 个压力组合、89 个主互通用例**：Mihomo 42、Itsusinn TUIC 2、Xray-core 17、V2Ray-core 9、shadowsocks-rust 4、官方 Hysteria2 3、Caddy 前端 3、MASQUE 9。这是静态选端数量，Caddy 为 factory 分类，其实际协议处理层按上节记录，不是网络通过数量。

普通 Mieru 九项、HY2 mTLS 及可表达的 Salamander、VLESS TCP ECH、客户端字段观察和 HY2 取消边界使用 Mihomo；SS2022 半关闭 EIH 使用 shadowsocks-rust。TrustTunnel 的 H3 独立代表消费同一主目录，不因入口不同默认切换官方 endpoint。

公共压力生成器发送 IP 目标，不以 Trojan domain-UDP 名称宣称验证域名编码；TCP／WS／gRPC 基础压力路径使用 Mihomo。真实域名编码由主互通用例对 Xray-core 验证。静态选端、配置生成、离线检查或短前检均不能代签正式压力。

历史结果保留原服务端、版本、源码与负载身份，不自动代签新的路由或后续版本；客户端始终为 Vole、Mihomo。已接受的整体覆盖见[最终覆盖结论](../conclusions/full-pressure-final.md)，协议事实和未知边界分别见[协议结果](protocol-results.md)与[已知问题](known-issues.md)。平台和真机另行验收。
