# Linux 测试内核

Apple container 的新建 ARM64 容器默认使用 **7.3.0-vole-kata430**，并配套官方 **TCP Brutal 2.0.1** 模块。下述缓存、模块签名和已验证能力属于这一 Apple ARM64 环境；Windows 的 `wslc` 使用实际 WSL session 内核，不能使用这里的 ARM64 Image 或模块为其代签，详见 [Windows / wslc](windows-wslc.md)。

两后端均使用官方 Ubuntu 26.04 LTS、NAT；构建容器为 5 CPU／16 GiB，运行容器为 5 CPU／4 GiB，构建与负载不重叠。每次运行记录实际 guest 架构与内核身份；旧结果保留原输入，不因后端或默认内核更新而重新签署。

## 最终配置与缓存

内核基于官方未修改的 Linux 7.3 源码和 Kata 4.3.0 的配置基线，开启 `CONFIG_MPTCP=y`、`CONFIG_MPTCP_IPV6=y`、`CONFIG_MODULES=y`、`CONFIG_MODULE_UNLOAD=y`、MPTCP／TCP 诊断及模块签名。VirtIO 块设备、网卡、控制台、vsock、virtiofs、TUN 与根文件系统驱动保留内建，保留 Kata 的 `CONFIG_CRYPTO_FIPS=y` 及相关加密配置。

最终缓存为 `.cache/kernels/kata-4.3.0-7.3-arm64/`：

| 产物 | SHA-256 |
| --- | --- |
| `Image-7.3.0-vole-kata430-brutal-arm64` | `8a0a8851aa10ffa9bea6348d9b6e918743ef3795345c584d51a5bf6e7ff9dec0` |
| `brutal.ko` | `b7b88df0db0eaa056be34d8fb26641ce18fbb4909b7a320d5176ca187287ea71` |

同目录保留最终配置和公钥 `brutal-kernel-signing-cert.x509`。Image 内建证书与模块签名匹配；官方 TCP Brutal 源码未修改，签名私钥及构建树已删除。默认安装的 Image 与表中摘要一致，新建客户端及服务端容器均已读回 `7.3.0-vole-kata430`。

模块由需要它的自有 guest 夹具加载；设置默认 Image 不会自动向每个容器提供模块。各 guest 必须使用匹配模块并具有加载权限，6.18.56 的模块不能用于 7.3。Core 不加载模块、不修改全局拥塞算法或宿主网络。旧 6.18.56 与显式对端 Image 的共享缓存保留原身份，不作为当前默认环境。

## 已验证能力

真实 raw-IP TUN 验证已确认 TCP／UDP 数据、内容、半关闭及资源清理；MPTCP 实际协商且无 fallback。TCP Brutal 双端回读 2.0.1、算法 `brutal` 及 2,000,000 B/s 参数，双向各 1 MiB 完整交付，实际发送和 ACK 计数有效。模块签名可信，仅有外置模块 `O` taint，没有不可信签名或强制加载标记，系统默认 BBR 不变。

切换默认内核后的既有 Core `ff1cbd7` 普通 CLI，已通过真实 TUN 的 `brutal-h2mux-local-present` 功能验证，包括双端实际 Brutal、配置的 3 Gbps 速率、超过 11 秒无反向载荷上传、TCP／UDP 内容、半关闭、Controller、同步 Stop、模块卸载和清理。配置速率与有限功能通过不等于正式压力达标。

## 已确认边界

相同最小 socket 夹具经真实 TUN 传输 32 MiB 后，6.18.56 的 MPTCP 上传在连接关闭约 3.1 秒时仍有 51.78125 MiB 的 memcg `memory.stat sock` 计费残留；该版 TCP 上传为零。7.3 的 TCP／MPTCP 上传和下行四项均为零，已验证字节、摘要、FIN 和实际 MPTCP 协商。计费残留不是进程 RSS，也不等于同量物理内存驻留；此对照不承担吞吐或 CPU 验收。旧版仅测上传，不补签其下行。

源码对照支持 7.3 已具备父 MPTCP socket 的 accept 充账、已有及后加入 subflow 继承 memcg 的完整链路；未逐提交二分，不能宣称单一提交独立修复。6.18.56→7.3 的配置迁移也包含 PREEMPT 变化，不能称为单变量内核对照。

MPTCP 双子流验证已在两条真实 TUN 逻辑路径上完成协商、数据和路径退出；父 fd 的接口／源地址绑定不能约束全部子流，该出口约束 FAIL 保留。路径恢复后的附加 FIN 等待超时仍未区分内核重建与夹具时序，不归因为 Core 缺陷；没有验证独立物理多路径。

当前压力结论见[结果总览](benchmark.md)和[最终覆盖结论](../conclusions/full-pressure-final.md)。这些 Linux 内核与容器结果不代表 Apple、Android、Windows 或真机验收；平台、真机及 iOS／tvOS physical footprint 继续暂缓。
