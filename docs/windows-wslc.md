# Windows / wslc

Windows 宿主使用原生 Python／uv 编排，通过 `wslc.exe` 管理 Linux 容器。macOS Apple Silicon 继续使用 Apple 官方 `container`。容器后端按宿主选择，协议、负载、观察器和验收口径共用现有实现。

## 环境与入口

- 安装 Python 3.11+、uv，以及包含 `wslc.exe` 的 WSL；在 PowerShell 中确认 `wslc version` 可用。编译负载生成器还需要与宿主架构匹配的稳定版 Go。Microsoft 的[入门文档](https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-containers)说明 `wslc` 随 WSL 提供。
- 从 Windows checkout 运行命令，`--source vole=PATH` 使用明确的 Windows 绝对路径。宿主目录通过 `wslc` bind mount 交付；容器内路径保持 Linux 语义。
- AMD64 Windows 使用 Linux AMD64 guest，ARM64 Windows 使用 Linux ARM64 guest。Rust toolchain、官方对端产物及缓存身份随 guest 架构选择；已有另一架构的 ELF 不能复用。

在 benchmark 根目录执行离线入口：

```powershell
uv run --locked container-benchmark interop --list
uv run --locked container-benchmark stress --list
uv run --locked container-benchmark compare --list
uv run --locked container-benchmark experience --list
uv run --locked container-benchmark self-test
```

这些入口不启动容器或网络负载。开发依赖可通过 `UV_PROJECT_ENVIRONMENT` 放入工作区 `references` 下的外置环境；正式运行共享缓存和单次材料仍分别使用工程的 `.cache/`、`.work/`。

## 容器合同

两后端使用同一官方 `docker.io/library/ubuntu:26.04` 标签，按实际架构冻结 digest，并读回 Ubuntu 身份、容器资源和内核版本。专用编译容器保持 5 CPU／16 GiB；客户端、协议对端、原站和负载容器使用 5 CPU／4 GiB。编译完成并清理 builder 后才启动负载。

Windows 使用带工程标签的独立 bridge NAT 网络，核验 IP masquerade 与 MTU 1500。容器不发布宿主端口；Controller 仍只用于管理。创建、检查、执行和清理均通过 `wslc`，清理前后按精确名称与所有权标签核对，保留既有容器、网络、映像及宿主 VPN、路由、DNS 和防火墙。

`wslc` 的列表 JSON 与 Apple `container` 不同：列表可能为逐行 JSON，完整 inspect 为数组；后端统一解释名称、标签、状态、IP、CPU 和内存。资源限制必须按实际 inspect 回读，不能把请求值当作实际分配。

## 真实 TUN 前提

所有网络验证继续要求隔离容器中的真实 raw-IP TUN，以及既定 namespace、路由、DNS、正常 Stop／join 和清理证据。运行前检查 `wslc run` 是否提供所需的 `--cap-add`、`--cap-drop`；能力缺失时停止运行，不改用宿主网络或普通代理入站代替。

官方 [3.0.5 预览版](https://github.com/microsoft/WSL/releases/tag/3.0.5)提供这两个 capability 选项；3.0.3 不提供，运行前检查会拒绝该版本。`/dev/net/tun` 缺失时，真实 TUN 夹具在容器内创建字符设备节点，再执行 `TUNSETIFF`；节点存在或参数被接受都不单独证明真实数据通路可用。

WSLC 的 IPv4 bridge 默认可能令容器的 `net.ipv6.conf.all.disable_ipv6` 和 `net.ipv6.conf.default.disable_ipv6` 为 1，而真实 TUN 夹具需要配置私有 IPv6 地址。Windows 运行容器在启动时为自己的 namespace 启用这两项并严格读回 0；仅在需要修改时重挂载该容器的 `/proc/sys`。专用编译容器不执行这一步，interop 容器仅在明确获得 `SYS_ADMIN` 的 TUN／namespace 场景执行。全部设置随自有容器删除而释放，不修改 Windows 或 WSL session 的全局设置。这不为 bridge 增加外部 IPv6 地址或连通性，相关场景仍须另行核验。

平台 TUN／namespace 及小量 TCP、UDP、DNS 验证，与 Vole 协议互通、压力和设备验收分别记录；任何一种通过都不能替代另一种。

## 内核与结果边界

`wslc` 使用 WSL session 的实际内核。逐容器记录 `uname -r`；`--peer-kernel` 的逐容器自选 Image 在此后端不可用，传入时明确拒绝。工程不自动修改 WSL 全局内核、session 设置或系统网络。

Apple ARM64 的 `7.3.0-vole-kata430` 与签名 TCP Brutal 模块只适用于[原环境](kernel-environment.md)。Windows 的 MPTCP、Brutal、IPv6 和内核行为须分别验证，缺失能力保留为未执行或明确错误，不能引用旧 Apple 容器结果。Windows 编排下的 Linux CLI 测量也不代签 Vole Windows VPN／Wintun 或物理设备验收。

新后端的运行保留实际源码、架构、映像、内核和负载身份。旧账本不会因切换到 Windows 自动重新执行；验证受影响旧 PASS 时显式使用 `--retest-passed`，历史结果保持原输入。
