# Vole / Mihomo TUN benchmark

本工程负责隔离环境中的协议互通、Vole 原生 TUN 压力及 Vole／Mihomo 同负载比较。
结果见 [Benchmark 总览](docs/benchmark.md)与[整体 1Gbps 最终结论](conclusions/full-pressure-final.md)。
互通、有限体验、性能、编译、原生 ABI 与设备验收分别解释；旧结果保留原源码、对端、输入和判定。

## 授权与隔离

实验仅使用自有容器、隔离网络命名空间、合成流量和测试身份；通过 NAT 连接，不发布宿主端口。
宿主只承担编排、编译与离线分析，保留宿主 VPN、路由、DNS、防火墙及无关资源。
正式依赖可作为输入下载，公共服务不作为负载目标。
所有网络业务，包括 CLI、Invoke／FFI、DNS、生命周期、互通和性能检查，都经过真实 raw-IP TUN，
并核验实际 TUN 流量及正常 Stop／join／清理；Controller 只作管理入口。离线检查和编译不要求 TUN。
被测客户端不配置 HTTP／SOCKS 入站；官方对端的对应 listener 只用于验证出站协议。

抓包、会话密钥和解密仅限明确需要的自有合成测试，按最小必要范围收集；不写入最终结论，随临时资源清理。
委派任务必须写清目标、允许文件与动作、排除项、自有资源、数据／密钥边界、宿主隔离和清理 owner。
具体要求见 [AGENTS.md](AGENTS.md)。

## 固定环境与输入

- Apple Silicon macOS 与 Apple 官方 `container`；全部自有 guest 使用官方 `docker.io/library/ubuntu:26.04`，每会话冻结 digest 并读回 `VERSION_ID`。
- 专用编译容器为 5 CPU／16 GiB；客户端、协议服务端、原站与负载容器为 5 CPU／8 GiB。builder 停止并清理后才启动负载。
- guest 在启动 Core／对端前固定并核验 `hostname=benchmark`；默认内核为 ARM64 `7.3.0-vole-kata430`，MPTCP 与匹配签名的 TCP Brutal 模块按所选场景使用。
- 当前默认 1Gbps，每窗 60 秒，分别运行 TCP、UDP、mixed。2Gbps 和显式 3Gbps 专项单独选择，不加入当前默认矩阵。
- 默认 64 条业务流，每个 UDP 源 socket 轮换 64 个目的端口；单目标例外以窗口输入为准。1Gbps 是全部流、上下行与两条 CN 分支的合计应用载荷供给。
- 额外叠加 1000 QPS 唯一名称 DNS；命中／未命中 CN 分支各承担一半业务。DNS 不计入业务带宽，保持 DIRECT。
- 两客户端启用回环 Controller，负载前请求 `/connections`，测量期间保持空闲。同容器实例使用不同回环端口。
- 固定同一官方 MetaCubeX/meta-rules-dat revision 的完整非 lite `geosite.dat`／`geoip.dat`，加载完整 `geosite:cn`／`geoip:cn`，保留正反见证。额外 MRS／MMDB／DB／MetaDB／ASN 也来自同一官方仓库并记录身份；仅在用户明确要求时改变分类。
- 两客户端 TUN／eth0 的 `txqueuelen` 均为 4096，启动前与停止后读回；原站队列保持默认。qdisc、socket 缓冲、线程和其他 Core 参数使用生产默认值。
- 协议服务端使用 2MiB UDP 默认接收缓冲，核验实际内核和新 socket 值，结束后恢复。只有 MASQUE/IP、WireGuard 的窗口关闭自有原站 eth0 TSO，并回读、恢复；其他原站设置保持默认。
- 官方依赖每日检查一次最新稳定版，每会话冻结实际版本、源码、镜像、规则与二进制 SHA256；矩阵不固定旧运行版本。可执行文件从已验证缓存独立复制，数据文件可硬链接。

Vole 必须显式传入 `--source vole=PATH`，不推断父／兄弟 checkout。
构建使用普通 Release CLI：`cargo build --locked --release --no-default-features --features cli --lib --bin vole`。
Mihomo 使用官方稳定二进制。双方复用同一 Go 负载、TUN 设施、外部 PID 观察器与统计实现；
原生 TUN 栈、域名提示与 GeoData 表示差异照实记录，不宣称内部实现等价。

## 主入口

先用离线目录选择范围，再执行已授权的真实 TUN 工作负载：

```sh
uv run --locked container-benchmark interop --list
uv run --locked container-benchmark stress --list
uv run --locked container-benchmark compare --list
uv run --locked container-benchmark experience --list
```

```sh
uv run --locked container-benchmark interop \
  --source vole=/absolute/path/to/Vole
uv run --locked container-benchmark compare \
  --source vole=/absolute/path/to/Vole \
  --rates 1000 --seconds 60 --rounds 3 \
  --transports tcp udp mixed --protocols vless-xhttp-reality anytls
uv run --locked container-benchmark stress \
  --source vole=/absolute/path/to/Vole \
  --vole-binary /absolute/path/to/linux/vole \
  --campaign --reference-on-failure --rates 1000 --seconds 60 \
  --transports tcp udp mixed --protocols vless-tcp-plain
uv run --locked container-benchmark experience \
  --source vole=/absolute/path/to/Vole --scenarios daily mixed-slow
```

`interop --protocol`／`--backend`选择功能代表，仍由[服务端选择合同](docs/server-selection.md)校验实际协议端。
`compare`比较两客户端；`stress`验收 Vole，并可按失败追加同输入 Mihomo。
`--protocols all`选择压力目录，TCP-only 节点的 UDP／mixed 为 N/A。
`--smoke-only`仅执行功能前检，不能代替 60 秒正式窗口。
`experience`另有 `single-tcp`、`high-concurrency`，各场景按有限任务或独立容量口径解释，不互相代签。

`--vole-binary`只跳过编译；来源必须与同摘要的构建记录配对，实际版本字符串不证明构建来源。
已有 CLI 缺少 builder-only rlib 时，离线 GeoData 加载探针记未执行，运行时完整 CN 正反见证仍必需。
`--geoip-format metadb`选择同一官方快照的完整 MetaDB，不与 Mihomo 客户端对照同时使用；默认 DAT。
额外 domain MRS 使用 `--domain-rule-set /path/to/cn.mrs --domain-rule-witness www.qq.com`，
同时验证 GeoSite／MRS 正见证和真实 RULE-SET 命中，防止缺少域名元数据绕过。
`--peer-kernel /absolute/path/to/Image`只选择协议服务端 guest 内核，并记录文件与实际内核身份。

### 精确窗口与恢复

`stress --campaign --window-selection /path/to/windows.json`选择普通窗口：

```json
{"vmess-v2ray-h2-plain": ["tcp"], "tuic-uot-v2": ["udp", "mixed"]}
```

`--tls13-window-selection /path/to/tls13.json`使用同格式，仅允许 Vision 的 TCP，表示独立的 TLS1.3 应用窗口。
两份选择可单独或合并使用；省略 `--protocols`时按文件推断，显式给出时必须与组合并集一致。
普通选择不自动增加 TLS1.3 业务，省略的流量不补跑；档位仍由 `--rates`选择。
选择可与 `--list`离线核对，正式窗口、检查点与完成计数共用同一精确集合。

默认跳过选择内已有有效正式通过证明的窗口；受影响旧 PASS 必须显式添加 `--retest-passed`。
历史 FAIL、ERROR、前检、参考和其他负载不能抵扣本批回归。
单组最多 10 个同协议组合，组内／组间串行，每 5 组或尾批保存检查点；H3 smux 独立最后。
详见[批量编排](docs/batch-orchestration.md)。

## 专用功能入口

以下模块位于 `container_benchmark.interop`。常用形式为
`uv run --locked python -m container_benchmark.interop.MODULE --source vole=PATH --binary CLI --output .work/reports/NAME.json`；
支持的 `--case`／`--list`以各模块参数定义为准。夹具存在、离线列举与真实业务通过分别记录。

| 功能 | 模块或定位 |
| --- | --- |
| 出口接口／mark／代理链 | `egress_policy`；可省略 binary 由共享构建器准备 |
| 功能出站、进程身份、订阅输入 | `functional_outbounds`、`process_rules`、`provider_input` |
| Controller 推送、鉴权、在线配置、维护 | `controller_streams`、`config_apply`、`maintenance` |
| DNS 过期缓存、rematch、前台控制 | `dns_stale`、`deferred_control`、`foreground_control` |
| 流式安全身份、REALITY、ShadowTLS/JLS | `security_wrappers` |
| SS2022 半关闭、EIH、官方 ShadowTLS | `ss2022_half_close`；`--clients vole mihomo --official-shadowtls` |
| SS2022 obfs／WebSocket 插件 | `ss_plugins`；独立插件 namespace 与 Mihomo 解码层 |
| HY2 Gecko／Realm、TUIC SNI／pin | `quic_clients` |
| 配置字段、证书轮换与选路 | `client_inputs` |
| Core 自建 TUN、mark、IPv6、启动回滚 | `native_tun_network` |
| IPv4／IPv6 被动 TCP PMTU | `passive_pmtu`；`--family 4`可选单族 |
| 固定普通 CLI 的 TUIC／TrustTunnel／MASQUE／主动 PMTU | `final_representatives --mode tuic|trusttunnel|masque|masque-pmtu` |
| 显式 QUIC 预算下降注入 | `final_representatives --mode masque-budget`，另需 `--diagnostic-patch`与`--diagnostic-identity`，不证明生产自动重探测 |
| 受控 QUIC socket／GSO／ECN／故障边界 | `quic_socket`；`--source`是裸 checkout 路径，省略`--run`仅列举，执行必须显式`--run` |
| MPTCP／TCP Brutal 功能与原生消费者 | `tcp_options`；binary 与 library 二选一，实际协商／fallback、Stop和资源分别验收 |

MPTCP／Brutal 的功能及 FFI 示例：

```sh
uv run --locked python -m container_benchmark.interop.tcp_options \
  --source vole=/absolute/path/to/Vole --binary /absolute/path/to/linux/vole \
  --output .work/reports/tcp-options-cli.json
uv run --locked python -m container_benchmark.interop.tcp_options \
  --source vole=/absolute/path/to/Vole --library /absolute/path/to/linux/libvole.so \
  --output .work/reports/tcp-options-ffi.json
```

压力代表为 `vless-tcp-plain-mptcp`与`vless-tcp-tls-h2mux-brutal`，通过主 `stress`入口显式选择。
MPTCP 使用独立 listener 的 `inbound-mptcp`；Brutal 仅在使用它的自有 guest 核验／加载匹配模块，
不改变系统默认拥塞算法，关闭 socket 后只卸载本夹具加载的模块。
这些夹具不声明 MPTCP 与 Brutal 叠加支持；有 protect／接口／源地址约束时必须保留既有出口策略及安全 fallback。

### HTTP、MITM 与原生 ABI

```sh
uv run --locked python -m container_benchmark.interop.http_processing \
  --source vole=/absolute/path/to/Vole --binary /absolute/path/to/linux/vole \
  --library /absolute/path/to/linux/libvole.so \
  --output .work/reports/http-processing.json
uv run --locked python -m container_benchmark.interop.http_generations \
  --source vole=/absolute/path/to/Vole --library /absolute/path/to/linux/libvole.so \
  --output .work/reports/http-generations.json
uv run --locked python -m container_benchmark.http_pressure \
  --source vole=/absolute/path/to/Vole --binary /absolute/path/to/linux/vole \
  --profile h12 --output .work/reports/http-pressure.json
```

`http_processing`覆盖 URL／头／正文改写、跨 origin 凭据清除、选择性 TLS、H1／H2、
原站内容与来源及 Stop；可选 library 追加 Linux 无界面 Invoke 宿主合同。
`http_generations`通过生产 Invoke／Free 验证 CA 与活跃连接的配置代次。
CA 使用独立 `0600`材料文件，不安装系统信任，私钥随临时资源删除。
`http_experience`与`http_body_experience`使用同样的 source／binary／output 参数，
分别验证五状态日常／少量慢连接，以及四个 H1／H2 正文有限任务；有限体验不套用定速性能门槛。

`http_pressure`默认 streaming 九窗，`--profile h12`为十窗；支持离线`--list`及模式／速率／流量筛选。
纯 UDP 只验配置隔离，不证明 HTTP／MITM 命中；实际改写、原样回放、业务字节、内容和独立原站封账分别记录。
主动 rewrite／MITM 没有等价 Mihomo 处理器，参考验收不适用。

ECH／GREASE／H3 透明旁路使用 `interop.http_transparency`，除 source／binary／output 外，
传 `--boring-out /path/to/boring-sys-build/out`和`--boring-include /path/to/boring-sys-build/out/boringssl/include`。
输入须来自同一 Linux ARM64 Core 构建；复用已构建 BoringSSL 公共 API，不修改第三方源码。

## 指标口径

- **吞吐**：60 秒活动窗口内实际接收载荷，包含错误内容及错误返回前的部分 I/O；`goodput_mbps`沿用字段名，表示 raw 接收吞吐。实际发送、排空接收和目标配额另列。
- **CPU**：进程 CPU 秒／采样墙时×100%，100%为一个逻辑核。覆盖业务准备、运行、排空，排除编译、下载、Core初始启动、首次连通和最终Stop；墙时不必等于60秒。
- **RSS**：核验 PID／可执行文件身份后，20ms采样所得生命周期 VmHWM／VmRSS 最大值，覆盖启动至Stop／reap。快速退出的瞬时峰值可能不可见；`shutdown_observed`单列。`wait4`只作独立诊断，不作内存排名。
- **UDP交付丢包**：实际发送与固定收尾内唯一有效接收之差除以实际发送。上下行分列，合计按实际包数加权；坏包与重复包不抵消缺口，发送不足另记。
- **TCP完整性**：每流实际已发送前缀须在原期限内完整交付，内容、来源、摘要及结束状态均正确。普通窗口每流起点加63秒截止，活动期结束不再开始新记录；配额不足与实际字节缺口分开，不延长期限消除FAIL。
- **窗口与DNS**：各分支均达到计划活动时长才算完整。DNS skipped／timeout／SERVFAIL／REFUSED／迟到分列，错误回答不计成功；`driver_complete`或旧`load_reached`不单独代替这些证据。

双方同输入；多轮吞吐／CPU取中位数、RSS取生命周期最大值、UDP按实际发送包数加权。
TCP重传、内核UDP计数、负载侧CPU及停止后队列最大值均为独立诊断，不代替业务交付或Core指标。
不可用值写N/A，不补零。可选`BENCHMARK_MEMORY_DIAGNOSTICS=1`或`NativeProcess(..., memory_diagnostics=True)`
只启用有界外部快照，不作为正式峰值或压力PASS。
Linux RSS不代签iOS／tvOS扩展physical footprint，编译与Linux业务不代签平台／真机。

## 优化与验收策略

| 范围 | 吞吐下限 | UDP交付丢包上限 | Vole RSS |
| --- | --- | --- | --- |
| 1Gbps默认性能参考 | 950Mbps | 1% | ≤43MiB |
| 同输入Mihomo初期参考 | min(950, Mihomo实测)Mbps | max(1%, Mihomo实测) | ≤43MiB |
| 多轮结束后的精确窗口 | min(950, 0.9×Mihomo实测)Mbps | max(1%, min(100%, 1.1×Mihomo实测)) | ≤43MiB |
| 后续2Gbps／显式3Gbps过载 | 记录，不设性能门槛 | 记录，不设性能门槛 | ≤45MiB |

CPU独立记录。性能、完整性、内存、测量、DNS、实际TUN、正常Stop／join和清理分别判断；
综合通过必须满足全部适用门禁。TCP不套用UDP丢包率，完整性失败不改写性能状态。
过载允许有界丢包／断连保护内存，仍须完成窗口并验证已接收内容与来源，保留截断、未完成量和原错误状态。

性能未达标时补测同一协议、服务端、规则、负载、队列和环境的Mihomo；兼容／完整性错误与指标可测量性分开，
实际吞吐、CPU、RSS和丢包仍记录。没有可测匹配对照时使用默认参考，不能用其他客户端或旧窗口代替。
客户端固定为Vole与Mihomo，服务端按[字段顺位和明确例外](docs/server-selection.md)选择，失败本身不构成换端理由。

优化先对照本地Mihomo、clash-rs和官方实现，区分Core／对端／benchmark，再按实测瓶颈采样和修改。
允许渐进改善与合理指标取舍，不设单次改善幅度下限；不能把实际业务减少当作收益，受影响窗口仍须满足门禁。
每个精确窗口最多20个独立生产候选；原版、重复、纯观测、仅编译／内存检查不计新轮。
多轮后可明确原因提前结束严格阶段；相对10%资格只用于已登记的服务端、流量、速率、TLS、地址族、队列与负载，
按相对比例计算，不加百分点，不放宽内存、完整性、DNS或生命周期。

运行账本`conclusions/pressure-passes.json`保存历史通过证明，`conclusions/optimization-rounds.json`保存资格和证据指纹，
均属于正式运行输入，不随过程材料删除；历史证据标识不代表过程文件仍保留。
新阶段使用独立评估，不覆盖旧PASS／FAIL／ERROR、UNKNOWN或原源码身份。
公共层改动先登记受影响旧PASS，再用相同输入与`--retest-passed`显式回归；历史通过证明不能代签修改后源码。
场景与门禁详见[验证策略](docs/validation-strategy.md)。

## 离线检查

```sh
uv run --locked container-benchmark self-test
uv run --locked ruff check .
uv run --locked ruff format --check .
```

离线检查不启动服务／容器；生产编译和Rust内存／配置回归由显式Vole源码工程负责。
仅运行已请求的网络smoke／矩阵，离线结果、功能互通、性能及设备／发布验收分别签收。

## 临时资源清理

共享验证依赖放`.cache/`，每次配置、证书、构建、日志和机器报告放`.work/`。
先保存经审阅的最终文字结论及正式运行账本，再停止、join并删除精确登记且标签匹配的自有容器与过程材料。
按任务保留必要的最终产物；保留已验证共享依赖、源码及无关资源。
每个TUN实例只逐条删除带本实例唯一comment的IPv4／IPv6 NAT规则，保留既有及其他实例规则；重复关闭不得重复删除。
设置与业务异常保留首因；清理或结论持久化失败时保留自有scratch及未回收记录，供原owner恢复。
