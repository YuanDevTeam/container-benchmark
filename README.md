# Vole / Mihomo TUN benchmark

本工程负责隔离环境中的协议互通、Vole 原生 TUN 压力及 Vole／Mihomo 同负载比较。
历史基线与适用范围见 [Benchmark 总览](docs/benchmark.md)。
互通、有限体验、性能、编译、原生 ABI 与设备验收分别解释；旧结果保留原源码、对端、输入和判定。

## 授权与隔离

实验使用自有容器、隔离网络命名空间、合成流量和测试身份。容器通过 NAT 连接，可按测试需要发布宿主端口。
macOS 综合压力用 socketpair 模拟包 I/O，原站和协议端在自有容器中运行，DNS 经 Mac carrier 到容器。所有路径均保留宿主 VPN、路由、DNS、防火墙及无关资源。
正式依赖可作为输入下载，公共服务不作为负载目标。
所有网络验收业务，包括 CLI、Invoke／FFI、DNS、生命周期、互通和性能检查，都经过真实 raw-IP TUN，
并核验实际 TUN 流量及正常 Stop／join／清理；Controller 只作管理入口。socketpair 诊断单独记录，不代替真实 TUN、真机吞吐或内存验收。离线检查和编译不要求 TUN。
被测客户端不配置 HTTP／SOCKS 入站；官方对端的对应 listener 只用于验证出站协议。

抓包、会话密钥和解密仅限明确需要的自有合成测试，按最小必要范围收集；不写入最终结论，随临时资源清理。
委派任务必须写清目标、允许文件与动作、排除项、自有资源、数据／密钥边界、宿主隔离和清理 owner。
具体要求见 [AGENTS.md](AGENTS.md)。

## 固定环境与输入

- 容器在 Apple Silicon macOS 使用 `container`，在 Windows 使用 `wslc`，guest 架构匹配宿主。编译和测试复用最新 Ubuntu LTS 的依赖镜像，预装公共依赖及稳定 Rust、Go。每天核对来源，依赖变动时重建，每会话冻结镜像和工具链。详见 [依赖镜像](docs/prepared-image.md) 和 [Windows / wslc](docs/windows-wslc.md)。
- 专用编译容器为 5 CPU／16 GiB；客户端、协议服务端、原站与负载容器为 5 CPU／4 GiB。builder 停止并清理后才启动负载。
- 全部自有容器使用最新维护中的 **7.3 stable** 自编译内核。启动后核验内核配置、MPTCP enabled=1、可信的匹配 TCP Brutal 模块及默认 BBR，实际 MPTCP 协商和 Brutal socket 按场景核验。 [内核环境](docs/kernel-environment.md)
- 当前默认 1Gbps，每窗 60 秒，分别运行 TCP、UDP、mixed。2Gbps 和显式 3Gbps 专项单独选择，不加入当前默认矩阵。
- 默认 64 条业务流，每个 UDP 源 socket 轮换 64 个目的端口；单目标例外以窗口输入为准。1Gbps 是全部流、上下行与两条 CN 分支的合计应用载荷供给。
- 多端口／端口跳跃协议组合的完整候选端口集合展开、去重后最多50个，在监听或端口发布前核对；范围及实施状态见[端口预算](docs/port-budget.md)。
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
`--peer-kernel /absolute/path/to/Image`显式输入仍须与本次冻结的最新 stable 内核身份一致，不能绕过全部容器的共享内核门禁。

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
MPTCP 使用独立 listener 的 `inbound-mptcp`；Brutal 模块在全部自有 guest 的环境前检中加载，
业务夹具借用该能力并单独核验实际 socket，不改变系统默认拥塞算法；模块随自有 VM 清理。
这些夹具不声明 MPTCP 与 Brutal 叠加支持；有 protect／接口／源地址约束时必须保留既有出口策略及安全 fallback。

`brutal-h2mux-local-absent` 要求本地缺少模块，与全部容器预先加载 Brutal 的环境合同冲突，现标记为 `NOT_APPLICABLE`，`--list` 显示原因。只选择此项时直接保存不适用结果，不准备依赖或创建容器／网络资源；与适用项混选且其余项通过时，总结果为 `PARTIAL`。旧的模块缺失测试保留原环境和判定，不改签为新基线的通过证明。

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
该旧 `http_pressure` 范围的主动 rewrite／MITM 没有等价 Mihomo 处理器，等价处理参考验收不适用。
独立版本的 [Mac 全负载压力](docs/mac-full-pressure.md) 使用公共 Rust 发生器，分别执行 `js`／`mixed` 的 1 Gbps 综合窗口；其默认性能目标为 800 Mbps／适用 UDP 丢包≤1%，Mac Core worker `phys_footprint`≤45 MiB。该Mac JS范围在精确窗口完成严格优化阶段后使用40%比例差距：吞吐≥min(800,0.6×Mihomo实测)、UDP丢包≤max(1%,min(100%,1.4×Mihomo实测丢包率))；阶段资格及其他门禁保持。显式追加的 Linux Mihomo real-TUN 参考使用 `mihomo-raw-delivery-v1`，只按实际发送／接收载荷和交付比例测量容量，不校验内容或完整性；部分交付与零接收照实计量。Mihomo 使用原文协议处理，不执行 MITM／JS，平台、协议栈和调度差异单列；旧 Linux 950 Mbps、10%阶段及历史判定保持原范围。

ECH／GREASE／H3 透明旁路使用 `interop.http_transparency`，除 source／binary／output 外，
传 `--boring-out /path/to/boring-sys-build/out`和`--boring-include /path/to/boring-sys-build/out/boringssl/include`。
输入须来自同一 Linux ARM64 Core 构建；复用已构建 BoringSSL 公共 API，不修改第三方源码。

## 指标口径

- **吞吐**：60 秒活动窗口内实际接收载荷，包含错误内容及错误返回前的部分 I/O；`goodput_mbps`沿用字段名，表示 raw 接收吞吐。实际发送、排空接收和目标配额另列。
- **CPU**：进程 CPU 秒／采样墙时×100%，100%为一个逻辑核。覆盖业务准备、运行、排空，排除编译、下载、Core初始启动、首次连通和最终Stop；墙时不必等于60秒。
- **Apple平台内存**：macOS模拟与iOS／tvOS新窗口正式考查 `phys_footprint`，上限45MiB。Mac读取独立Core worker的Mach内核lifetime峰，覆盖初始化、业务、排空、Stop／destroy及观察器join后的最终读取；其后的回包序列化与退出尾段不冒称已观测。真机读取整个NE的footprint，两者owner范围仍不同。缺少有效footprint保持不可用，不回退RSS。
- **参考内存／RSS诊断**：Linux核验PID／可执行文件身份后，20ms采样生命周期VmHWM／VmRSS最大值，覆盖启动至Stop／reap；快速退出的瞬时峰值可能不可见，`shutdown_observed`单列，`wait4`作为独立诊断。Mac保留精确worker的Darwin `wait4.ru_maxrss`，Apple真机保留NE resident，均不替代Apple正式footprint门禁。
- **Vole UDP交付丢包**：实际发送与固定收尾内唯一有效接收之差除以实际发送。上下行分列，合计按实际包数加权；坏包与重复包不抵消缺口，发送不足另记。Mihomo新raw参考使用实际接收包数及比例，详见其独立合同。
- **Vole TCP完整性**：每流实际已发送前缀须在原期限内完整交付，内容、来源、摘要及结束状态均正确。普通窗口每流起点加63秒截止，活动期结束不再开始新记录；配额不足与实际字节缺口分开，不延长期限消除FAIL。
- **窗口与DNS**：各分支均达到计划活动时长才算完整。DNS skipped／timeout／SERVFAIL／REFUSED／迟到分列，错误回答不计成功；`driver_complete`或旧`load_reached`不单独代替这些证据。Vole要求严格完成。Mihomo 对照保留窗口与 owner 证据，DNS 计划、实际发送、未发送及回答情况仅作诊断。

双方同输入；多轮吞吐／CPU取中位数，内存按明确的平台指标保留各自owner的峰值，UDP按实际发送包数加权。
TCP重传、内核UDP计数、负载侧CPU及停止后队列最大值均为独立诊断，不代替业务交付或Core指标。
不可用值写N/A，不补零。可选`BENCHMARK_MEMORY_DIAGNOSTICS=1`或`NativeProcess(..., memory_diagnostics=True)`
只启用有界外部快照，不作为正式峰值或压力PASS。
Linux、Android、Windows的客户端内存仅作参考：保留各平台真实指标，取消RSS预算与仅内存不可用的验收阻断，不改名为footprint或代签Apple验收。编译与Linux业务不代签平台／真机。

## 优化与验收策略

| 范围 | 吞吐下限 | UDP交付丢包上限 | Apple内存上限；其他平台参考 |
| --- | --- | --- | --- |
| 1Gbps默认性能参考 | 950Mbps | 1% | ≤45MiB |
| 同输入Mihomo初期参考 | min(950, Mihomo实测)Mbps | max(1%, Mihomo实测) | ≤45MiB |
| 多轮结束后的精确窗口 | min(950, 0.9×Mihomo实测)Mbps | max(1%, min(100%, 1.1×Mihomo实测)) | ≤45MiB |
| 后续2Gbps／显式3Gbps过载 | 记录，不设性能门槛 | 记录，不设性能门槛 | ≤45MiB |

Apple平台内存上限统一为 **≤45MiB（47,185,920字节，含等值）**，不按带宽、性能参考阶段或体验场景分档。共享 `memory_policy.py` 按实际客户端OS选择政策：Mac模拟考查独立Core worker的 `phys_footprint`，iOS／tvOS考查整个NE；RSS只作附加诊断。Linux、Android、Windows使用 `informational`、`limitBytes=null`，内存大小或仅内存读数缺失不影响业务验收，报告显示“参考／不设门槛”。OOM、异常退出、身份错误和未正常Stop／join仍是失败。缺少Apple正式footprint证据不能用RSS或旧诊断采样补齐。历史测量、门槛和PASS／FAIL不追改；政策变动不代表已重跑。统一接口和平台能力边界见[客户端内存政策](docs/client-memory.md)。

CPU独立记录。Vole 的性能、完整性、适用内存门禁、测量、DNS、实际TUN、正常Stop／join和清理分别判断；
综合通过必须满足全部适用门禁。TCP不套用UDP丢包率，完整性失败不改写性能状态。
过载允许有界丢包／断连保护内存，仍须完成窗口并验证已接收内容与来源，保留截断、未完成量和原错误状态。

性能未达标时补测同一协议、服务端、规则、负载、队列和环境的 Mihomo。容量对照只比较实际接收吞吐与 UDP 丢包率。丢包率以实际发包为分母，未发送单列。内容、交付完整性及发送配额完成情况不作门禁，CPU、RSS 和传输错误作为参考。Mac 全负载的实际计数边界见[参考合同](docs/mac-full-pressure.md#linux-mihomo-协议容量参考)。
缺少有效身份、窗口、计数或生命周期证据时，匹配参考仍不可用，使用默认参考；不能用其他客户端或旧窗口代替。
客户端固定为Vole与Mihomo，服务端按[字段顺位和明确例外](docs/server-selection.md)选择，失败本身不构成换端理由。

优化先对照本地Mihomo、clash-rs和官方实现，区分Core／对端／benchmark，再按实测瓶颈采样和修改。
允许渐进改善与合理指标取舍，不设单次改善幅度下限；不能把实际业务减少当作收益，受影响窗口仍须满足门禁。
每个精确窗口最多20个独立生产候选；原版、重复、纯观测、仅编译／内存检查不计新轮。
多轮后可明确原因提前结束严格阶段；相对10%资格只用于已登记的服务端、流量、速率、TLS、地址族、队列与负载，
按相对比例计算，不加百分点，不放宽适用内存门禁、完整性、DNS或生命周期。

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

## Mac 模拟

`mac_full_campaign` 以 socketpair 模拟 TUN，按协议运行 1 Gbps 的纯 JS 与 JS 加内置规则窗口，支持断点、回归和 Linux Mihomo 参考。 [Mac 全负载压力](docs/mac-full-pressure.md)
