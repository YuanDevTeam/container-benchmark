# 主线验证的最终范围

本页汇总已完成的编译、有限Linux功能与原生ABI结论，按实际源码和产物分别签收。
当前压力接受源码为clean `6c3e3c2`，主465项与队列外5项的[最终结果](../conclusions/full-pressure-final.md)
采用未受影响来源继承及受影响回归，不表示下列旧源码平台／ABI检查已在该提交重跑。
逐窗口压力指标见[协议结果](protocol-results.md)，未关闭问题见[已知问题](known-issues.md)。

## 已验证的Linux FFI产物

普通Linux ARM64 FFI来自clean Core `3fdee4608e0a42d8592267671a6e2f79444f6240`，
benchmark `17d0f094b284f770b60d7d7e37e0362043f9f934`。
构建为Ubuntu26.04、5CPU／16GiB，与负载分开，源码冻结、正常join及自有资源清理通过。
实际命令：`cargo build --locked --release --no-default-features --features ffi --lib --message-format=json-render-diagnostics`。

| 产物 | 字节数 | SHA-256 |
| --- | ---: | --- |
| 当时配套普通CLI | 25,971,864 | `577311dc8d3d2776ff1fc75ec920b4058918a552ee8b5c65408cd6d061c325ec` |
| libvole.so | 25,185,448 | `500d0ac63011b339f04ae95017ab898264fee1fc3188cf9aeebb2ae39d9eab92` |
| libvole.a | 400,291,410 | `efa67fd72431c2e858a5ee5b78a937f6441408485fb51da78ced5d55573b66fc` |
| vole.h | 557 | `ef069d1935f9593a9a1ee5512138e266b1f57411bf80eead04bcb89d08f6504c` |

CLI实际构建源码为`36a0b6f`；`3fdee46`相对它仅修改验收文档，生产代码相同，不能称CLI在`3fdee46`重编。
动态库验证为AArch64 ELF，静态库为ar归档，动态导出包含`VoleInvoke`／`VoleFree`，头文件来自同源构建。
该FFI完成构建、文件格式、导出与摘要校验，**没有重新执行ABI／真实TUN业务**。
原构建identity指纹为`5a3f4f85105b9f19d1079f3e679b24150e353c2bbd103345872154fee942bce2`，不改挂后续源码。

## `62a82b5`的有限Linux验收

受验Core为`62a82b5213575e0933f76a31024e88a38f653846`，普通CLI SHA-256为
`bc47424e4f96b2b5a0c4443c2c31869910fd595f3ce9e8830aca7052970eb911`。
以下使用自有隔离Ubuntu26 NAT、真实TUN、合成原站及既定官方对端，无宿主端口。
它们是有限功能证据，不是完整压力、后续库ABI、平台或真机验收。

### 受控QUIC socket

| 场景 | 结果 | 物理UDP socket | 独立接收数据报 | 注入故障 |
| --- | --- | ---: | ---: | ---: |
| native4 | PASS | 2 | 1370 | 0 |
| native6 | PASS | 1 | 1325 | 0 |
| packet4 | PASS | 1 | 2372 | 0 |
| gso-failure4 | PASS | 2 | 1842 | 1 |
| ecn-setup-failure4 | PASS | 2 | 1680 | 1 |

原逐物理inode／分段FNV校验、来源、完整TCP／UDP、同来源bulk-HOLD、MARK、GRO／ECN、
活动Stop、实际TUN及清理通过。故障只影响被注入owner，其他source stripe保持原生路径。
接收端仅关闭可控rx-gro，rx-gro-hw仍fixed-on，环境为`PARTIAL_RX_CONTROL`；没有请求改变客户端TX。
旧聚合观测不足与业务前feature控制ERROR保留，不据此判Core分段失败。
close观察器仅记录调用前标记，实际资源释放由正常Stop／join独立证明；protect callback未在本工具验收。

### DIRECT DoQ与强制H3 DNS

官方dnsproxy为v0.86.0、revision `f2a42ab8563bf782c8c131b03ef2eb44569e7c9e`，
二进制SHA-256 `bbf337d83d0f4af83f82c2c5ee052c04861ed028b5d4d8e041d3d91a345ae8f4`，为该会话实际冻结身份。

| 路径 | warm／sibling／held并行／恢复 | 实测单次upstream期限 | 正常Stop／物理inode／TUN／peer join |
| --- | --- | ---: | --- |
| DIRECT DoQ | PASS | 3.006810335秒 | PASS |
| 强制H3 | PASS | 3.002705835秒 | PASS |

完整DNS wire、固定A／AAAA、Core正常SIGINT／exit0和资源释放通过。
实测为配置的3秒单次attempt；5秒总预算到期为`NOT_EXERCISED`，prefer-H3竞速未验。
Core→peer新请求缺少逐请求物理观察，记`UNOBSERVED`，不能从origin计数推断零物理包。
peer独立重试／排空与Core业务、Stop分别验收，历史夹具及peer终止ERROR未改签。

### 真实TUIC两代ABI

受验为同源码普通ffi-only `libvole.so`，SHA-256
`cf37871f56b053dd86444c9fa84f548573993f98c546d7eec8583740ca4068f2`，没有为该验收修改或重编。
真实`VoleInvoke`／`VoleFree`在同进程、同runtime、同已加载库中运行两代实例；
TCP1024B及UDP64／1200B双向内容、摘要、来源、GRO=0物理socket、活动Stop后零继续转发、
Internet owner释放、借用TUN保持、旧ID拒绝与新代状态通过，ABI响应28次、释放28次。

每代Destroy恢复完整原B0加**同一对**进程级信号socket；逐descriptor及flags、同一fd／inode／mode和单创建事件均核验，
没有按AF_UNIX类别或任意新增两个fd豁免。该pair的创建模块与锁定Tokio1.53.1／Mio1.2.3的信号通道角色已确认。
原`raw_full_B0_restored=false`保持；runtime clone、epoll、eventfd、Controller、网络和TUN复制分别释放。
当前内核未启UNIX_DIAG，peer inode=0不用于判泄漏；历史全FD／诊断ERROR保留。
不外推共享库卸载、静态C宿主或Apple／Android／Windows行为。

## 已完成的旧源码跨平台构建

Core `1e12828`的普通构建完成Linux ARM64 CLI／FFI、macOS ARM64 CLI与host检查、
Apple FFI六Rust目标／五切片XCFramework，以及Android arm64-v8a／x86_64。
macOS ARM64 C ABI的version／validateConfig调用及buffer释放、Android架构与七项C／JNI导出通过；
当时C ABI业务仅覆盖Mieru provider代表路径，不扩称全协议或设备调用。
同源22项显式纯内存、27项代表互通、DoH／H3、CLI／Invoke及五条活动生命周期的Core范围通过，
MASQUE H3/IP UDP参考端见证ERROR保留。Apple／Android为该源码收尾后的单次正式构建，
本地Boring保持`4bac7612`来源；未执行的架构、Windows和设备范围不补签。

本表绑定clean Core `9f3fd33`及本地Boring `4bac761`，不是当前`6c3e3c2`重编或设备运行。

| 平台 | 已完成范围 |
| --- | --- |
| Linux ARM64 | 普通Release CLI／FFI、C ABI版本／配置校验／释放、七项精确定向回归通过 |
| macOS | ARM64／x86_64 CLI编译与架构；ARM64原生`-h/-v`及文件／stdin配置校验、FFI导出和C ABI冒烟通过；Intel只有编译／架构检查 |
| Apple FFI | iOS／iOS模拟器、macOS双架构、tvOS／tvOS模拟器六目标及五切片XCFramework；headers／modulemap／架构通过 |
| Android FFI | arm64-v8a／x86_64 Release、ELF、每ABI七个C／JNI导出、同NDK匹配的C++ runtime通过；没有设备运行 |

框架当时未包含许可证文件，没有执行签名或tag release；本地Boring构建通过不代签公开依赖与许可发布门禁。
更早`6aa4d62`Linux CLI／FFI及tvOS compile-check仅签各自当时范围，不替代上述统一构建或后续设备验收。

## 其他保留的功能结论

| 实际源码／产物范围 | 最终有效结论与限制 |
| --- | --- |
| `9b48b49` Linux FFI，SHA-256 `4c748f061ab48ddceb938c30f9ecb43f5891308e66bd248c55289f9c151ebd52` | 真实TUN的CA轮换、活跃H2授权与配置代次通过；坏证书／私钥候选拒绝，旧连接保持旧策略，新连接采用新CA；Stop约2.05ms、之后无原站请求、借用TUN／路由保持。不是全部H2并发或设备信任库验收 |
| `0f73f47` Linux普通CLI | Core hosts／非hosts经真实resolve1／NSS与TUN查询，Stop后两个新名称经物理接口解析、路由／DNS／NSS设置恢复通过；systemd PID1部署、后续system／DHCP切换与真机未验 |
| `102b4ab`普通CLI | TrustTunnel H3 TCP／UDP-health真实TUN通过；功能修复不代签新的H3定速压力或稳定性能收益 |
| `102b4ab`外置补丁的独立诊断构建 | MASQUE显式revalidation＋受控peer丢包实现native UDP1400→1200、DATAGRAM1372→1172，原TCP／UDP、局部IPv6 drop及Stop／清理通过；不声明生产自动重探测 |
| `82d902b` HTTP有限体验 | 四个原128KiB/s慢上传真实TUN窗口通过；旧初轮缺失日志，不追溯认定同一根因，不代签1Gbps或长期稳定 |
| `102b4ab`六窗＋`9f3fd33`等价生产实现十二窗 | 18个HTTP定速窗中九个1Gbps基础目标与九个3Gbps内存压力通过；3Gbps H2未完整交付、缺trailer及原`FAIL_DATA`保留，不能据聚合`loss_bytes=0`称零丢失 |

更早`5a96018`的22个协议代表和10个功能模块真实TUN结果只签当时目录与产物，
其中已退出能力的kcptun／mKCP不恢复为当前验收项。
原`b95d24d`的42个正式压力窗口仍为24PASS／17FAIL／1ERROR，不因后续修复、互通或构建改签为整体验收通过。
短请求原站关闭竞态归属benchmark夹具修复，不能写成Core已修复旧故障。

## 尚未签署的范围

| 范围 | 状态 |
| --- | --- |
| `6c3e3c2`完整FFI ABI／TUN及Apple／Android／Windows重新构建／业务 | 本轮NOT RUN；不继承为同产物实测 |
| `3fdee46`新FFI的ABI／真实TUN业务 | NOT RUN，只有构建／格式／导出／摘要检查 |
| Windows原生构建、UWP／WinRT／Wintun | NOT RUN |
| NE／JNI／protect、平台权限、真机VPN网络与生命周期 | NOT RUN |
| iOS／tvOS扩展physical footprint、设备整进程内存 | NOT RUN；Linux RSS不能代签 |
| 静态C宿主、共享库卸载、5秒DNS总预算到期、prefer-H3竞速 | 本页有限Linux验收未覆盖 |
| 当前2Gbps、高并发、少量慢连接及Linux system／DHCP专项 | 继续暂缓；已有旧体验或旧系统DNS结果不代签当前专项 |
| systemd PID1部署、真实WARP、签名／部署／发布、公开Boring许可门禁 | NOT RUN |

Mieru自然EOF、上传期限及其他未闭合归因继续为UNKNOWN，性能政策通过不能关闭完整性问题。
已知缺陷及旧FAIL／ERROR的最终状态集中保存在[已知问题](known-issues.md)，不由构建或离线回归代签。
本页只保留最终文字与必要产物指纹；过程报告、观测日志和临时诊断材料已按清理范围移除。
