# 客户端内存政策与观测接口

内存政策按被测客户端实际运行的OS选择，不能按编排宿主选择。Windows宿主经`wslc`运行的Linux ELF仍是Linux客户端；Apple `container`也运行Linux。新平台接口只预留，不表示已实现或通过Android／Windows客户端测试。

| 客户端 | 政策 | owner与正式指标 |
| --- | --- | --- |
| macOS模拟 | `budget`，≤45MiB（47,185,920字节，含等值） | 独立Core worker的Mach `physical_footprint`内核lifetime峰 |
| iOS／tvOS真机 | 相同预算 | whole NE的footprint，不使用前台App或RSS替代 |
| Linux | `informational`，无数值门槛 | 实际Core PID的RSS/HWM，保留来源、范围与缺失状态 |
| Android（接口预留） | `informational` | Emulator guest的进程RSS/HWM、阶段PSS等，非宿主模拟器进程内存 |
| Windows（接口预留） | `informational` | 真实Windows进程的working set/private commit等，非Linux容器或VM总内存 |

Apple的Mach字段`phys_footprint`在报告中沿用`physical_footprint`名称；metric别名不改变实际账本。Mac最终自读在Core stop／destroy及观察器join之后，其后的回包序列化与进程退出尾段不冒称已覆盖。来源、PID与最终读取资格保持必要，缺footprint不能拿RSS或旧诊断采样补位。

`informational`不是一个自动PASS的内存门禁：`requiredForAcceptance=false`、`limitBytes=null`、`gateMet=null`，预算状态为`NOT_APPLICABLE`。能读到的内存正常记录，读不到时保留null／不可用及原因；内存大小与仅内存采集失败不影响业务验收。CPU关键观测、进程身份、完整窗口、内容、DNS、真实TUN、正常退出和join按原要求判断。真实OOM／LMK、意外退出与强杀仍失败，不能仅凭大RSS猜测OOM，也不能把取消预算当成取消容器/VM资源隔离上限。

## 公共接口

`memory_policy.py`集中提供：

- `policy_for(client_platform)`：返回平台政策、required metric/statistic、预算及是否参与验收。
- `assess_memory(client_platform, observation, qualified=..., applicable=...)`：只消费显式指标与峰值来源，不采样进程，不替换OS指标。
- `memory_gate_allows(assessment)`：仅预算政策要求有效PASS；参考政策不阻断其他有效证据。
- `execution_scope(client_os, client_arch, backend, tun_kind)`：冻结客户端平台、架构、执行后端、TUN类型和内存policy身份，用于报告及恢复证明。

观测事实与政策分别保存。当前值、采样最大值、内核lifetime高水位保持独立，使用bytes并注明来源API、owner、实际观测覆盖和缺失原因；sampled max不能改名成kernel peak。多个进程的峰值之和不是同一时刻的客户端总峰值，RSS也可能重复计算共享页。

Android／Windows的provider预留只返回显式未实现／不支持状态；本次不启动AVD、VM或容器，不承诺Wintun/WinRT VPN已具备容器能力。后续实现时必须先核验实际平台和真实TUN能力，再安排压力验证。

## 报告与恢复

新Linux报告将`memory_policy`和`memory_assessment`独立列出，保留原RSS数值；`memory_limit_bytes`和`memory_limit_met`为null。checkpoint显示“参考／不设门槛”，缺值不会被补成零或误标成必要门禁UNKNOWN。

新通过证明保留原v1坐标与首个证明，并追加`execution_scope`。恢复必须显式提供匹配的clientOS、clientArch、backend、tunKind、memoryPolicyID，任何未知或不匹配都不复用。旧无scope证明不迁移、不覆盖；只有显式`legacy_linux=True`且独立旧来源能证明相同Linux平台、架构、后端、TUN及原严格内存通过时才允许兼容。无法核实这些身份时保持不复用，不能据同协议／速率／TLS坐标代签新平台。

历史报告保留当时的数值、门槛和结论。
