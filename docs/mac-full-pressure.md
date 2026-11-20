# Mac 全负载压力

Mac 客户端用 socketpair 模拟 TUN。原站、DNS 后端和协议服务端运行在自有 Linux VM。本入口覆盖 HTTP、HTTPS H1/H2、UDP、MITM 和 JS。

## 负载与指标

每个 profile 分别执行纯 `js` 与 `mixed`（原生规则后再执行 JS）。两种模式均开启 MITM 与 JS，使用 1 Gbps 综合供给、64 条流、60 秒活动及固定 10 秒排空。HTTP 请求和响应覆盖完整 64 KiB 正文，按上／下行、CN 命中／未命中等分。

| profile | 64 流分配 | 带宽分配 |
| --- | --- | --- |
| 支持 UDP | HTTP、HTTPS/H1、HTTPS/H2、UDP 各 16 流 | 每族 250 Mbps |
| 仅 TCP | HTTP 24 流、HTTPS/H1 20 流、HTTPS/H2 20 流 | 每族三分之一 |

额外叠加 1000 QPS 唯一名称 DNS，每查询期限 2 秒，走 Core 的 DIRECT 路径。使用同一 revision 的完整官方非 lite GeoSite／GeoIP，核验实际 CN／OTHER 分流。每个多端口代理组合启用前检查完整候选集合 ≤50。UDP 业务目标数按 profile 冻结。

- HTTP 请求完整提交正文后才算准入。活动边界未准入且没有原站收据的规定情形单列，其余准入前失败和已准入后的错误继续验收。GET 的请求正文为零，响应正文仍须完整改写。
- `js` 将原正文 `a` 改写为 `c`。`mixed` 先由内置规则改为 `b`，脚本验证该阶段后改写为 `c`。按原始 URL 匹配，独立原站收据和接收端验证实际正文。
- UDP 丢包率以实际发送为分母，接收端校验来源、内容和唯一交付。未发送单列。固定排空期内完成的在途发送按实际计数，活动期后的接收不计吞吐。
- 默认有效吞吐 ≥800 Mbps，计活动期内完成验证的 HTTP 改写和唯一有效 UDP 字节。适用的加权 UDP 丢包 ≤1%。Mac 独立 Core worker 的 `phys_footprint` 峰值 ≤45 MiB。
- 正文完整性、TLS／ALPN、实际发送的 DNS 交付、分流、原站封账、对端身份与健康以及 Stop／destroy／join 分开验收。原生 HY2 跳跃使用官方对端，已有 nft 端口包计数只作诊断，缺少同一实际连接的跨端口业务证据时判定为 UNKNOWN。

## Linux Mihomo 协议容量参考

`--reference-on-failure` 显式开启。默认性能失败且 Mac owner 正常关闭、原站已封账时，在相同 owned origin／peer 上追加 Linux 真实 TUN 参考。使用官方稳定 Mihomo，通过原文处理测量容量。Mac 与 Linux 构建绑定共同 Rust 发生器及 h2 来源，分别记录平台、二进制、驱动和输入身份。

原始容量采用 `mihomo-raw-delivery-v1`，统计实际发送和接收载荷，包括部分传输。UDP 丢包为 `max(0, 1 - received / sent)`。未发送量另记，全部未发送时丢包率不可用。固定排空期收发计入交付比例，吞吐仅计活动期实际接收。内容、交付完整性、DNS 回答与发送配额完成情况作为诊断。

参考须具备实际收发计数、窗口、分流、真实 TUN、官方程序及正常封账和清理证据。匹配参考的初期门槛为 `min(800, Mihomo Mbps)` 和 `max(1%, Mihomo UDP 丢包率)`。精确窗口满足严格阶段结束条件后，才使用 40% 相对比例，门槛分别为 `min(800, 0.6 × Mihomo Mbps)` 和 `max(1%, min(100%, 1.4 × Mihomo UDP 丢包率))`。Vole 的完整性、改写、DNS、内存和生命周期规则继续独立生效。

## 运行与断点

`--list` 离线列出当前目录和轮次。按协议分组，每组最多 10 个组合，每轮最多 5 组串行。正式测量前需要当前构建在 DIRECT 的两个模式通过有限 P0。

```sh
uv run --locked python -m container_benchmark.mac_full_campaign --list
uv run --locked python -m container_benchmark.mac_full_campaign --run \
  --root "$OWNED_CAMPAIGN_ROOT" --source "$CORE_SOURCE" \
  --assets "$FULL_GEODATA_DIRECTORY" --revision "$GEODATA_REVISION_40HEX" \
  --image "$PREPARED_IMAGE" --binary "$MAC_DRIVER" \
  --binary-sha256 "$MAC_DRIVER_SHA256" --build-record "$MAC_BUILD_RECORD" \
  --origin-build "$ORIGIN_BUILD_RECORD" --peer-artifacts "$PEER_ARTIFACTS" \
  --output "$PUBLIC_OUTPUT" --preflight-only
```

使用 `python -m container_benchmark.mac_http_build --root "$OWNED_BUILD_ROOT" --source "vole=$CORE_SOURCE"` 构建 Mac driver。冻结 Core 与 benchmark 源码、driver 及其构建记录、Go 原站构建、peer artifacts、GeoData 和依赖镜像。为每次运行创建独立目录。Linux 参考须提前构建，再同时传入 `--reference-on-failure` 和 `--reference-build`。

- `--preflight-only` 只做有限诊断。正式窗口省略该选项。
- `--profiles` 选择组合并自动补入 DIRECT。`--window-ids` 选择当前轮的精确待测或待回归窗口。
- `--checkpoint` 恢复已保存的输入、报告关联、历史通过与候选义务。`--advance-round` 在本轮允许推进时进入下一轮。明确登记受影响的已通过窗口后执行回归。
- `--candidate-record` 登记新的 Core 生产候选。`--checkpoint-action` 支持关闭严格阶段、关闭保护回归或清理义务、结束候选和准备最终回归。记录格式以 [campaign 校验器](../src/container_benchmark/mac_full_campaign.py) 为准。

保存断点时一同保留输出目录里的逐窗报告。恢复检查报告与冻结输入的摘要。一次性迁移生成的旧断点由对应历史版本读取，当前入口明确拒绝这类迁移数据。发生器或负载变化需重新冻结并完成当前构建 P0，旧结果继续按其实际构建记录。
