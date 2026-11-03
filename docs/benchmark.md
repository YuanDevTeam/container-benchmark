# TUN benchmark 最终结果

**主465项＋额外5项**按现行标准完成。主窗口最高RSS **42.80078125MiB**，接受窗口均≤43MiB；默认、严格Mihomo参考及多轮后相对阶段分别判断。结果由实际来源继承与受影响回归组成，不代表540项均在同一最终源码下通过。

- [完整470项四指标和18项匹配Mihomo参考](protocol-results.md)
- [压力验收最终结论](../conclusions/full-pressure-final.md)
- [已知问题及暂缓范围](known-issues.md)
- [互通、ABI和平台范围](mainline-validation.md)
- [验收策略](validation-strategy.md)

## 代表组合

以下仅展示七个组合的本轮最终值。Linux ARM64普通Release、真实TUN、Controller、完整CN GeoData、1Gbps／60秒。CPU100%为一核，RSS覆盖启动至Stop/reap。不同单位仅在同类指标内比较；纯TCP的UDP丢包为N/A，不画成零。

| 代号 | 组合 |
|---|---|
| P01 | `vless-tcp-none` |
| P02 | `vless-vision-reality` |
| P03 | `vless-xhttp-h1-tls-packet-up` |
| P04 | `vless-xhttp-h2-tls-stream-up` |
| P05 | `vless-xray-xhttp-h3-packet-up` |
| P06 | `2022-blake3-chacha20-poly1305` |
| P07 | `hysteria2-native-brutal-salamander` |

```mermaid
---
config:
  xyChart:
    height: 920
    width: 1100
---
xychart-beta horizontal
    title "纯 TCP"
    x-axis ["P01 Mbps 999.835", "P02 Mbps 999.922", "P03 Mbps 998.349", "P04 Mbps 997.624", "P05 Mbps 995.990", "P06 Mbps 999.712", "P07 Mbps 996.252", "P01 CPU % 40.418", "P02 CPU % 45.880", "P03 CPU % 48.195", "P04 CPU % 126.565", "P05 CPU % 115.118", "P06 CPU % 49.465", "P07 CPU % 155.511", "P01 RSS MiB 29.691", "P02 RSS MiB 31.879", "P03 RSS MiB 42.199", "P04 RSS MiB 38.672", "P05 RSS MiB 40.379", "P06 RSS MiB 31.082", "P07 RSS MiB 35.727"]
    y-axis "实际值（单位见标签）" 0 --> 1100
    bar [999.834692, 999.922074, 998.34921, 997.623945, 995.989914, 999.712358, 996.252058, 40.4182, 45.880342, 48.195215, 126.56481, 115.118483, 49.464973, 155.51099, 29.691406, 31.878906, 42.199219, 38.671875, 40.378906, 31.082031, 35.726562]
```

```mermaid
---
config:
  xyChart:
    height: 920
    width: 1100
---
xychart-beta horizontal
    title "纯 UDP"
    x-axis ["P01 Mbps 999.949", "P02 Mbps 999.940", "P03 Mbps 999.825", "P04 Mbps 999.853", "P05 Mbps 998.822", "P06 Mbps 999.584", "P07 Mbps 994.772", "P01 CPU % 170.657", "P02 CPU % 191.290", "P03 CPU % 172.402", "P04 CPU % 213.499", "P05 CPU % 197.395", "P06 CPU % 204.372", "P07 CPU % 222.794", "P01 RSS MiB 24.496", "P02 RSS MiB 32.031", "P03 RSS MiB 41.258", "P04 RSS MiB 38.051", "P05 RSS MiB 39.387", "P06 RSS MiB 30.816", "P07 RSS MiB 37.051", "P01 UDP丢包 % 0.000", "P02 UDP丢包 % 0.001", "P03 UDP丢包 % 0.004", "P04 UDP丢包 % 0.005", "P05 UDP丢包 % 0.000", "P06 UDP丢包 % 0.036", "P07 UDP丢包 % 0.512"]
    y-axis "实际值（单位见标签）" 0 --> 1100
    bar [999.94944, 999.94, 999.82528, 999.85344, 998.82176, 999.584, 994.77152, 170.65704, 191.290235, 172.401925, 213.498626, 197.395315, 204.371813, 222.794447, 24.496094, 32.03125, 41.257812, 38.050781, 39.386719, 30.816406, 37.050781, 0.0, 0.00072, 0.004384, 0.00488, 0.0, 0.036416, 0.511889]
```

```mermaid
---
config:
  xyChart:
    height: 920
    width: 1100
---
xychart-beta horizontal
    title "混合 TCP / UDP"
    x-axis ["P01 Mbps 999.942", "P02 Mbps 999.951", "P03 Mbps 999.916", "P04 Mbps 999.942", "P05 Mbps 999.915", "P06 Mbps 999.935", "P07 Mbps 983.349", "P01 CPU % 144.149", "P02 CPU % 172.421", "P03 CPU % 139.477", "P04 CPU % 199.669", "P05 CPU % 166.731", "P06 CPU % 167.789", "P07 CPU % 206.803", "P01 RSS MiB 27.176", "P02 RSS MiB 31.625", "P03 RSS MiB 42.125", "P04 RSS MiB 36.656", "P05 RSS MiB 39.531", "P06 RSS MiB 30.859", "P07 RSS MiB 37.980", "P01 UDP丢包 % 0.000", "P02 UDP丢包 % 0.000", "P03 UDP丢包 % 0.000", "P04 UDP丢包 % 0.000", "P05 UDP丢包 % 0.000", "P06 UDP丢包 % 0.000", "P07 UDP丢包 % 1.727"]
    y-axis "实际值（单位见标签）" 0 --> 1100
    bar [999.941517, 999.950637, 999.915917, 999.941997, 999.914797, 999.935277, 983.349169, 144.14928, 172.4214, 139.476956, 199.668774, 166.730951, 167.789211, 206.803178, 27.175781, 31.625, 42.125, 36.65625, 39.53125, 30.859375, 37.980469, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.726564]
```

## 专项最终结论

- MetaDB国家匹配投影（Core c66757b对389fe56）在真实TUN六窗降低RSS 6.33–7.95MiB；CN匹配器计入常驻容量由8,423,579降至202,953字节，容量不等于进程RSS。1Gbps按当时参考通过，3Gbps仅签当时内存过载，不代签当前2Gbps或其他数据集。
- H2请求future装箱（6c3e3c2）将目标TCP RSS由43.08594降至42.80078MiB；三项受影响窗口通过，正文mixed RSS和三窗CPU代价保留，最终表见压力结论。
- XUDP发送编码分配减少，但未证明稳定的整进程RSS或CPU收益；少量1Gbps混合重复未复现持续CPU回归。
- [四类体验最终基线](experience-baseline.md)：日常与少量慢连接完整交付；高并发RSS45.50MiB仍FAIL，暂缓优化，不混入通过的470项。

本次清理不新增网络测试，不改写历史FAIL。原始过程已删除，最终文字、指标、已知边界与正式测试入口保留。
