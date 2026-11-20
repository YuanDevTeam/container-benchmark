# Linux 测试内核

所有自有编译和运行容器使用最新维护中的 **Linux 7.3 stable**。每次会话核对 [kernel.org 发布列表](https://www.kernel.org/releases.json)，冻结源码、配置、工具链、Image 与匹配的签名 TCP Brutal 模块。环境不符时在编译或负载之前停止。

## Apple container

由执行者使用冻结的官方 Linux 源码与 Kata 配置基线构建 ARM64 Image。配置保留 VM 启动、VirtIO、TUN 和文件系统能力，并开启以下选项。

- MPTCP 与 IPv6 MPTCP
- 模块加载与卸载、强制模块签名
- SYSCTL、modversions 与 Basic modversions

保存上游与产物 SHA-256、源码签名核验、最终配置和模块公钥。每台 VM 通过 `--kernel` 使用显式 Image。普通运行读取 `.cache/kernels/apple-arm64-current.json`。能力复验可显式传入 `LinuxGuest(..., kernel_manifest=PATH)`，候选通过启动、能力核对和正常关闭后再更新默认清单。

在所有构建和负载入口核对以下实际读数。

- guest 架构与运行内核和冻结记录一致。
- `/proc/sys/net/mptcp/enabled` 为 `1`。
- 匹配签名的 Brutal 模块已加载，算法已注册且版本正确。默认拥塞算法为 BBR。

基础设施使用 `SYS_MODULE` 加载受信任模块。MPTCP 连接须另外验证协商，Brutal 场景须另外验证业务 socket。内核前检只证明环境能力。

## Windows / wslc

以 WSL session 的实际内核和模块作为独立输入。Apple ARM64 Image 及其模块仅供对应 Apple VM 使用。共享内核核验适用于各后端。 [WSL 前提](windows-wslc.md)

专用编译容器使用 5 CPU／16 GiB，运行容器使用 5 CPU／4 GiB。两者共用预制依赖镜像，编译容器须在负载开始前正常关闭。 [共享依赖镜像](prepared-image.md)
