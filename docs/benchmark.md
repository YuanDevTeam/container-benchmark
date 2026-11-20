# TUN benchmark 结果

Linux ARM64 真实 TUN 的 1 Gbps 历史基线包含 465 个主窗口和 5 个额外窗口。逐窗记录保留实际 Core、对端和门槛；历史基线包含多个源码身份。 [逐窗指标](protocol-results.md)

原 Linux 内存判定使用测量当时的 RSS 预算。当前 Linux、Android 和 Windows 的内存仅作参考。macOS 模拟与 iOS／tvOS 真机使用 45 MiB 的 `phys_footprint` 门槛，按各自进程范围验收。 [客户端内存政策](client-memory.md)

- [互通、ABI 与平台范围](mainline-validation.md)
- [已知问题及待验证范围](known-issues.md)
- [有限体验结果](experience-baseline.md)
- [当前验收策略](validation-strategy.md)
