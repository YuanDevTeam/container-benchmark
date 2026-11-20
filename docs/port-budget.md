# 多端口与端口跳跃预算

每个代理组合的完整候选集合展开去重后最多 **50 个端口**。候选包括主端口、区间和备用端口。业务 UDP 目的端口、Controller、原站、DNS 和临时源端口单独记录。

在启动任何测试资源前，用 [port_budget.py](../src/container_benchmark/port_budget.py) 校验整组声明及实际分配的端口。输入超限时拒绝整组，保留原因及未执行状态。合法 port hopping 至少有两个候选，运行时仍须核对实际换端口证据。

Vole 和 Mihomo 复用同一组候选、映射、跳跃参数及服务端。冻结并记录声明集合与观测端口。原生 Hysteria2 的固定 16 端口沿用其冻结 fixture。每组只发布必要端口，结束后由原 owner 释放。
