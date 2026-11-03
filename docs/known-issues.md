# 已知问题与验证边界

本页保留最终问题、责任边界和未验范围；运行日志、候选补丁、抓包、采样与逐轮过程已清理。通过性能参考不等于根因已修复，也不豁免内容、TCP实际交付或内存门槛。

## 当前压力接受范围

主465项和额外5项按各自实测来源及现行标准通过，详见[最终四指标](protocol-results.md)。这不是全部540项在同一最终二进制下重测通过，其余70项仅有历史身份，未签当前源码。主清单原11项未通过和原准备ERROR的结论保留，没有重写为当时已通过。

## Mieru

旧集中处置24项为23项性能有效通过，1项UDP载体标准编码TCP的对端／期限完整性FAIL。唯一701,216字节缺口与服务端正常Close时退休的535片连续DATA直接关联；这不解释首洞起因或所有自然EOF／上传期限停滞。其他EOF、原A2上传期限和少注入对照仍为UNKNOWN；健康复测不是故障修复。

已确认的Mihomo listener NAT错回和在途Close边界，分别保留[选端例外事实](../conclusions/mieru-tcp-nat-alias.md)与[Close边界](../conclusions/mieru-sdk-close-current.md)。按这些明确例外使用官方Mieru服务端；其他互通失败不构成换端许可。

UDP-pattern混合流的历史最终生产代码为36a0b6f，真实TUN 1Gbps／60秒、64流／64目标、DNS1000、IPv4／direct、队列4096，服务端为官方Mieru。

| 指标 | Vole | 匹配Mihomo |
|---|---:|---:|
| 实际吞吐 Mbps | 428.687 | 359.363 |
| CPU时间 秒 | 141.39 | 216.19 |
| RSS MiB | 33.293 | 591.688 |
| UDP丢包 % | 61.6488 | 58.3138 |

CPU在此为秒，不是百分比。经20个独立生产候选审计后，明确结束严格阶段；相对丢包差5.7191%在10%以内，上限64.1452%，故新阶段性能PASS，原严格FAIL不变。这是政策评估，不是新代码提升或重新负载。Vole的内容、32条实际TCP、DNS、完整窗口、内存和Stop另行通过；Mihomo自身TCP缺口53,360,488字节不剔除其实际吞吐，不豁免Vole完整性。

## TUIC v5

历史Mihomo v1.19.32服务端已直接证明一次发送侧16位随机Packet ID在旧片存活时复用，不同报文的互补片被拼成错误内容。此事件保留完整性FAIL；不外推为全部坏包均已逐项归因，也不宣称所有服务端或最新版仍有同一问题。仅无约束自增回绕也不能保证任意负载下不冲突；协议缺少跨片代次时，接收端不能普遍区分合法乱序与跨包互补片。

旧Mihomo quic-relay流信用耗尽和NAT回传退出有特定版本／拓扑的直接证据，原容量FAIL保留。客户端Mihomo与官方Itsusinn服务端曾有分片兼容错误，仍按真实收发统计吞吐并独立列完整性，不使用官方客户端替代Mihomo对照。当前选端合同不因这些旧失败重写，见[服务端选择](server-selection.md)。

## Smux与H3

Smux UDP接收socket溢出和RAW/TLS消费背压已观察，但尚未指定Core、Mihomo或Xray的唯一逻辑根因。旧Mihomo worker满队列的准备丢包与后续正式UDP容量问题是不同证据，不可混为已证同一原因。

读取合并、时钟和编码写帧候选均未形成全部保护通过的采用方案，生产保留6c3e3c2原路径。部分H3 UDP目标曾严格通过；原RAW控制和H3 UDP普通窗口经各自多轮后相对10%阶段有效通过，原严格FAIL保留，详见[最终压力结论](../conclusions/full-pressure-final.md)。

## 其他历史错误

- V2Ray-core稳定版5.53.0的传统H2曾出现服务端panic：Header called after Handler finished、退出2、OOM为零；后续相同版本窗口健康只表示未复现，触发交错仍UNKNOWN。
- 旧Xray 26.3.27曾在进程仍存活、OOM为零时缺少H3 UDP绑定端口，缺少直接关闭原因；连接idle或会话回收不能单独解释listener消失。后续新版本健康不等于已证明该旧故障修复。
- SS2022 EIH、WebSocket早数据及旧准备权限／清理ERROR的后续通过，不能证明原失败唯一原因。准备期规则源文件EACCES发生在Core启动前，与可执行权限或协议握手失败分别判断。

## 暂缓与未验

- [高并发体验基线](experience-baseline.md)：512连接时RSS45.50MiB仍超43MiB，优化暂缓；日常和少量慢连接通过不代签极限场景。
- 当前源码完整FFI ABI／TUN、Apple／Android／Windows平台和真机，以及iOS/tvOS整个扩展physical footprint未新增验收；旧有限结果见[主线范围](mainline-validation.md)。
- 2Gbps、高并发与少量慢连接进一步压力、Linux system／DHCP系统集成继续暂缓；1Gbps协议互通与压力通过不代签这些范围。
- DNS的真实5秒总预算到期、prefer-H3竞速与静态C消费者未由有限DoQ／forced-H3窗口签署。H3 MITM不支持，保留H1/H2 MITM和H3透明旁路。

正式测试、协议fixture、资源断言和受控socket门禁继续保留。删除过程材料不改变这些功能入口，不补造数据或自动放宽验收资格。
