# 共享依赖镜像

编译与测试统一使用预装依赖的 Ubuntu 镜像。公共依赖只在制作镜像时安装，后续容器直接使用已冻结的镜像；`install_tools` 保留调用接口，只检查镜像标记和已安装工具。

## 准备与复用

1. 每个本地日期核对官方 Ubuntu LTS 标签的原生架构 digest、APT 解析出的完整依赖包版本，以及官方稳定 Rust、Go 的版本和归档摘要。同一会话冻结输入，活动窗口期间不更新。
2. 用基础镜像身份、架构、请求依赖及解析版本、Rust／Go 身份和制作 recipe 生成 fingerprint。相同 fingerprint 跨日期复用镜像；基础镜像、依赖、工具链或 recipe 变化时制作新镜像。
3. 缓存命中时复核本地镜像身份。镜像不存在时从已核验的 OCI 归档恢复；归档、清单或镜像身份校验失败时重新准备，失败不能降级到裸 Ubuntu 或旧依赖。
4. 将本次镜像 reference、digest、基础镜像、包版本、Rust／Go 和 fingerprint 写入准备记录。编译／测试容器读回 Ubuntu 身份和镜像标记，随后核验需要的命令。

依赖镜像的公共入口为 `prepared_image.ensure_prepared_image`；压力／体验和旧 interop 入口共用该实现。`containers.shared_image` 返回派生镜像身份，官方 Ubuntu 拉取由 `containers.official_image` 负责，避免将本地派生镜像误当成 Ubuntu 官方 registry digest。

运行工具的逻辑入口限于 `/usr/bin`、`/usr/sbin` 及其 `/bin`、`/sbin` 别名，拒绝可写目录中的同名程序或符号链接。身份冻结保留最终文件的有界哈希与前后 stat 校验；Ubuntu 的 `env` applet 仅额外允许精确目标 `/usr/lib/cargo/bin/coreutils/env`，不开放其余 libexec 路径。

## 依赖变更

共享依赖集合定义在 `prepared_image.DEPENDENCY_PACKAGES`，覆盖 Rust／原生构建、协议测试、TUN／namespace、诊断和内核构建工具。场景额外依赖通过 `extra_packages` 传入并进入 fingerprint；不要在 `install_tools` 或活动窗口追加 `apt-get install`。

基础标签保持浮动并每日核对，每次会话使用其冻结 digest。公共 Cargo、Go 模块及官方协议端二进制继续按既有缓存和各自锁文件管理；依赖镜像不包含 Vole checkout、候选二进制、场景配置、测量数据或 MITM 私钥。更新被测源码不触发公共依赖镜像重建。

## 制作与隔离

镜像制作使用专用自有 builder，5 CPU／16 GiB；它从冻结的官方基础镜像安装依赖，再导出干净 rootfs 并生成 OCI 归档。此阶段同样执行[共享内核前检](kernel-environment.md)。完成后停止并清理 builder，再创建 5 CPU／4 GiB 的运行容器。

导出排除绑定挂载、`/proc`、`/sys`、`/dev`、运行时目录、临时文件及宿主注入的网络／身份文件。只缓存公共镜像和依赖身份；保留 benchmark 已有证书缓存，不把其中的私钥烘焙进镜像。镜像带工程限定命名与 fingerprint，按精确身份管理；不清理无关镜像或修改宿主 VPN、路由、DNS、防火墙。

镜像制作、缓存恢复和命中检查的通过，只证明准备流程。真实 TUN、协议、吞吐、内存和真机功能仍由各场景单独验证，旧结果保留原镜像与内核身份。
