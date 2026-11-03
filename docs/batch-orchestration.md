# 批量压力测试编排

当前正式执行默认1Gbps、每窗60秒，使用真实raw-IP TUN、Controller、完整官方CN GeoData及共享队列配置。
环境、指标和独立门禁见[README](../README.md#固定环境与输入)与[验收策略](../README.md#优化与验收策略)。
已完成范围见[最终结论](../conclusions/full-pressure-final.md)，逐窗口结果见[协议结果](protocol-results.md)；
这些结果不表示整个历史库存由同一最终二进制重测。

## 分组与检查点

`stress --campaign --reference-on-failure`始终只有一个活动组。
每组最多10个同一客户端代理协议的不同组合，组合与组之间均串行；
按代理协议归组，不按服务端实现、TLS后端或载体归组，同协议超过10个组合继续拆组。
DIRECT单独归组，每次campaign单轮；H3 smux独立排在所有普通窗口和参考之后。
每组拥有独立客户端、服务端与原站，仅准备本组所需入站；配置、端口及业务状态按组合隔离。

先完成本组各组合的真实TUN前检，再运行所选正式窗口，异常或未达标时追加同输入Mihomo。
每个组合仅一个原始前检，独立复检与参考单列；前检和低负载功能窗口不计正式压力数量。
H3 smux准备失败保留ERROR及未执行窗口，不改签PASS，也不改变普通队列结果。
每窗新建Core进程、真实TUN及客户端命名空间，覆盖启动至Stop／reap的RSS。
窗口前后核验对端进程、端口与cgroup OOM；计数增长、重置或不可用时记ERROR并停止后续窗口和参考，保留实际业务指标。

每完成5组保存检查点，尾批不足5组也保存；一组是一个完整容器组生命周期。
保存实际组合、精确窗口、独立门禁、PASS／FAIL／ERROR、未执行项、参考和剩余选择，先完成本组Stop／join及清理再进入下一组。
存在未通过项时标记`OPTIMIZATION_REQUIRED`，停止创建下一批并集中定位；测量完成不等于验收通过。
已确认的对端边界独立保留失败及处置结论，不据此切换服务端或放宽Core自身门禁。

## 精确选择与恢复

```sh
uv run --locked container-benchmark stress \
  --source vole=/absolute/path/to/Vole \
  --vole-binary /absolute/path/to/linux/vole \
  --campaign --reference-on-failure --rates 1000 --seconds 60 \
  --transports tcp udp mixed --window-selection /absolute/path/to/windows.json
```

普通选择为非空JSON“组合名→流量模式列表”，例如`{"tuic-uot-v2":["udp","mixed"]}`。
`--tls13-window-selection`使用相同格式，仅选择Vision的TLS1.3应用TCP；两份选择取并集，不自动补未选择窗口。
省略`--protocols`时按文件推断，显式给出时须与组合并集一致；档位由`--rates`独立指定。
两类选择均可与`--list`离线核对，无需源码、下载或容器。

标准60秒、完整CN DAT的campaign默认跳过`conclusions/pressure-passes.json`中有效基础／参考通过的精确窗口，
保留协议、流量、速率、TLS1.3变体、服务端与实际输入身份。全部已通过的选择不创建builder或容器；
部分通过的组合先前检，再执行剩余窗口。每个新通过窗口立即原子保存。
自定义时长、MetaDB、额外RULE-SET、非campaign和`--smoke-only`不使用或写入标准跳过账本。
源码或官方程序更新不自动清空历史证明；复测失败另记，不删除此前通过记录。

公共层变化先登记受影响的精确旧PASS，使用相同输入、选择和`--retest-passed`显式回归，包含清单外确实受影响的保护项。
旧通过不能抵扣新源码回归。恢复已中断批次只跳过本批已有有效通过的窗口，
保留FAIL／ERROR和集中处置选择；不能以未筛选的`all`冒充保存的剩余集合。
性能通过后结束该项性能优化，实际TCP缺口、未知归因或其他门禁继续独立处理。
相对10%阶段只消费`conclusions/optimization-rounds.json`中匹配的精确资格，不扩大到其他窗口。

## 服务端与冻结输入

[统一服务端合同](server-selection.md)在下载、配置与启动前校验顺位；`peer_selection`记录实际协议端、字段缺口、例外与辅助层。
Vole和Mihomo是固定比较客户端，沿用同一协议服务端；失败、准备ERROR或下载／构建失败都不构成换端理由。
TUIC native／quic使用Itsusinn，UoT v2及服务端mTLS字段专项使用Mihomo。
五个已确认listener缺陷的Mieru压力组合使用明确授权的官方mita，主互通保持原合同；两种服务端的通过记录独立。
分层XHTTP、Caddy、插件和TLS cover的辅助身份不能替代协议服务端身份。

官方依赖每天检查一次最新稳定元数据；每会话冻结首次选择的版本、源码、镜像digest、规则与ELF摘要，不在同轮中途换版。
编译型Go对端在专用builder完成并缓存，builder停止清理后才启动负载；运行guest只复制已验证程序。
同peer的batch与串行profile工作器共享组内已准备工具池，避免替换已访问的程序路径；
`auxiliary_tools`表示共享工具池，配置、证书与业务进程仍按profile隔离。

## 进程隔离与清理

各窗口保留实际owner、PID／启动身份、对端健康与输出读取状态，不以进程名进行宽泛回收。
Mieru UDP载体在前窗客户端正常Stop／cleanup后，由原PeerLab停止并join本组Mihomo／mita及固定TLS cover，再启动新进程；
真正首窗使用fresh进程，从TCP载体切至首个UDP窗也清除旧进程状态，TCP窗自身不额外重启。
TUIC quic-relay及其紧随窗口在相同边界重启本组TUIC／Mihomo和TLS cover，连续native窗继续复用。
这些规则不增加重试、缓冲、业务期限或等待；窗口前后健康必须属于同一代，代际重叠、意外退出与日志失败仍ERROR。

MASQUE/IP退出前核验活动流归零、网络会话／清理计数及无清理错误；Vole保留严格Stop。
Mihomo H3/IP参考只在有效测量、明确SIGINT、exit0且无自行退出／强杀时，允许独立的精确会话释放；
原三秒`protocol_idle: ERROR`继续保存，后续SIGUSR1回收另限三秒，不改写业务或原错误。
组结束统一Stop／join服务端，WireGuard最后停止以保持转发状态恢复顺序。

结论和剩余选择先持久化，再删除所属容器与scratch；保留正式运行账本和已验证共享依赖。
设置／业务异常保留首因，清理失败保留未回收记录供原owner恢复。
仅限自有Ubuntu26 NAT合成客户端、对端与原站，无宿主端口；宿主VPN、路由、DNS、防火墙及无关资源保持。
