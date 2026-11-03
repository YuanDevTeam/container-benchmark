# 1Gbps 最终逐组合结果

保存465个主窗口和5个不重复额外保护的最终文字结果，不含候选、诊断、短窗或中间重测。全部为真实Linux TUN、普通Release、60秒、Controller和完整CN GeoData。CPU100%表示一个逻辑核；RSS覆盖启动至Stop/reap；UDP丢包按上下行实际发送包数加权，纯TCP为N/A。全部接受窗口的实际TCP字节、内容和来源完整。

每行独立通过内存、完整性、DNS、负载及正常退出门禁。默认参考950Mbps／1%，不足时使用同输入Mihomo较容易逐指标参考；仅两项额外窗口使用自己的相对10%阶段。主窗按验收依据去重为452默认、13严格参考，其中1项严格参考也达默认。参考通过不等于全部组合达到默认值。[已知问题和暂缓范围](known-issues.md)。

## 实际代码来源

| 代际 | 已验证等价的生产代码 | 主窗口数量 |
|---|---|---:|
| 3fdee46 | 基线；普通CLI来自生产代码相同的36a0b6f | 70 |
| e774a51 | 普通H3 packet-up 48KiB | 23 |
| 2ce2b90 | H1 packet-up 48KiB | 365 |
| 6c3e3c2 | H2请求future装箱 | 7 |

未受后续局部修改影响的路径沿用已验证来源，不是同一最终ELF全量重测，也不重写原构建身份。Mihomo对照为实测v1.19.33，解码与辅助前端见[服务端合同](server-selection.md)；实测版本不是未来选版锁定。

## 协议主窗口（455项）

| 组合 | 流量 | 应用 | 对端 | Core代际 | 吞吐 Mbps | CPU % | RSS MiB | UDP丢包 % | 验收依据 |
|---|---|---|---|---|---:|---:|---:|---:|---|
| `2022-blake3-aes-128-gcm` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 154.889 | 30.777 | 0.000896 | 默认参考 |
| `2022-blake3-aes-128-gcm-shadowtls-v3` | mixed | 普通 | mihomo | 2ce2b90 | 999.756 | 173.151 | 32.797 | 0.016096 | 默认参考 |
| `2022-blake3-aes-128-gcm-shadowtls-v3` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 59.107 | 33.453 | N/A | 默认参考 |
| `2022-blake3-aes-128-gcm-shadowtls-v3` | udp | 普通 | mihomo | 2ce2b90 | 999.627 | 184.338 | 32.145 | 0.033376 | 默认参考 |
| `2022-blake3-aes-128-gcm-shadowtls-v3-uot-v2` | mixed | 普通 | mihomo | 2ce2b90 | 999.931 | 217.341 | 32.855 | 0.000000 | 默认参考 |
| `2022-blake3-aes-128-gcm-shadowtls-v3-uot-v2` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 57.308 | 32.711 | N/A | 默认参考 |
| `2022-blake3-aes-128-gcm-shadowtls-v3-uot-v2` | udp | 普通 | mihomo | 2ce2b90 | 999.938 | 227.890 | 32.953 | 0.000672 | 默认参考 |
| `2022-blake3-aes-128-gcm-uot-v2` | mixed | 普通 | mihomo | 2ce2b90 | 999.947 | 167.703 | 31.059 | 0.000192 | 默认参考 |
| `2022-blake3-aes-128-gcm-uot-v2` | tcp | 普通 | mihomo | 2ce2b90 | 998.908 | 44.036 | 30.762 | N/A | 默认参考 |
| `2022-blake3-aes-256-gcm` | tcp | 普通 | mihomo | 2ce2b90 | 999.546 | 44.032 | 31.008 | N/A | 默认参考 |
| `2022-blake3-aes-256-gcm-shadowtls-v3` | mixed | 普通 | mihomo | 2ce2b90 | 999.947 | 175.699 | 32.562 | 0.000000 | 默认参考 |
| `2022-blake3-aes-256-gcm-shadowtls-v3` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 60.649 | 33.312 | N/A | 默认参考 |
| `2022-blake3-aes-256-gcm-shadowtls-v3` | udp | 普通 | mihomo | 2ce2b90 | 999.964 | 195.702 | 32.023 | 0.000000 | 默认参考 |
| `2022-blake3-aes-256-gcm-shadowtls-v3-uot-v2` | mixed | 普通 | mihomo | 2ce2b90 | 999.940 | 210.701 | 32.887 | 0.000000 | 默认参考 |
| `2022-blake3-aes-256-gcm-shadowtls-v3-uot-v2` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 59.137 | 33.188 | N/A | 默认参考 |
| `2022-blake3-aes-256-gcm-shadowtls-v3-uot-v2` | udp | 普通 | mihomo | 2ce2b90 | 999.951 | 235.448 | 32.977 | 0.000000 | 默认参考 |
| `2022-blake3-aes-256-gcm-uot-v2` | mixed | 普通 | mihomo | 2ce2b90 | 999.946 | 169.520 | 30.570 | 0.000000 | 默认参考 |
| `2022-blake3-aes-256-gcm-uot-v2` | tcp | 普通 | mihomo | 2ce2b90 | 998.087 | 43.666 | 30.781 | N/A | 默认参考 |
| `2022-blake3-aes-256-gcm-uot-v2` | udp | 普通 | mihomo | 2ce2b90 | 999.953 | 190.361 | 31.184 | 0.000256 | 默认参考 |
| `2022-blake3-chacha20-poly1305` | mixed | 普通 | mihomo | 2ce2b90 | 999.935 | 167.789 | 30.859 | 0.000000 | 默认参考 |
| `2022-blake3-chacha20-poly1305` | tcp | 普通 | mihomo | 2ce2b90 | 999.712 | 49.465 | 31.082 | N/A | 默认参考 |
| `2022-blake3-chacha20-poly1305` | udp | 普通 | mihomo | 2ce2b90 | 999.584 | 204.372 | 30.816 | 0.036416 | 默认参考 |
| `2022-blake3-chacha20-poly1305-shadowtls-v3` | mixed | 普通 | mihomo | 2ce2b90 | 999.888 | 181.335 | 32.906 | 0.011872 | 默认参考 |
| `2022-blake3-chacha20-poly1305-shadowtls-v3` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 64.650 | 33.754 | N/A | 默认参考 |
| `2022-blake3-chacha20-poly1305-shadowtls-v3` | udp | 普通 | mihomo | 2ce2b90 | 991.027 | 204.468 | 32.301 | 0.888738 | 默认参考 |
| `2022-blake3-chacha20-poly1305-shadowtls-v3-uot-v2` | mixed | 普通 | mihomo | 2ce2b90 | 999.929 | 204.964 | 33.035 | 0.000992 | 默认参考 |
| `2022-blake3-chacha20-poly1305-shadowtls-v3-uot-v2` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 73.395 | 33.723 | N/A | 默认参考 |
| `2022-blake3-chacha20-poly1305-shadowtls-v3-uot-v2` | udp | 普通 | mihomo | 2ce2b90 | 995.324 | 236.064 | 32.984 | 0.013856 | 默认参考 |
| `2022-blake3-chacha20-poly1305-uot-v2` | mixed | 普通 | mihomo | 2ce2b90 | 999.917 | 180.742 | 30.777 | 0.000000 | 默认参考 |
| `2022-blake3-chacha20-poly1305-uot-v2` | tcp | 普通 | mihomo | 2ce2b90 | 999.896 | 47.486 | 30.871 | N/A | 默认参考 |
| `2022-blake3-chacha20-poly1305-uot-v2` | udp | 普通 | mihomo | 2ce2b90 | 999.921 | 198.592 | 31.043 | 0.003040 | 默认参考 |
| `anytls` | mixed | 普通 | mihomo | 2ce2b90 | 999.948 | 198.182 | 33.395 | 0.000000 | 默认参考 |
| `anytls` | tcp | 普通 | mihomo | 2ce2b90 | 999.109 | 50.696 | 36.309 | N/A | 默认参考 |
| `direct` | tcp | 普通 | direct | 3fdee46 | 998.297 | 44.704 | 30.035 | N/A | 默认参考 |
| `http-connect` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 44.399 | 29.246 | N/A | 默认参考 |
| `https-connect` | tcp | 普通 | mihomo | 2ce2b90 | 999.372 | 47.844 | 32.441 | N/A | 默认参考 |
| `hysteria2` | tcp | 普通 | mihomo | 2ce2b90 | 996.208 | 121.768 | 35.453 | N/A | 默认参考 |
| `hysteria2-gecko` | mixed | 普通 | mihomo | 2ce2b90 | 998.456 | 221.805 | 34.934 | 0.298529 | 默认参考 |
| `hysteria2-gecko` | tcp | 普通 | mihomo | 2ce2b90 | 996.829 | 157.945 | 35.914 | N/A | 默认参考 |
| `hysteria2-gecko` | udp | 普通 | mihomo | 2ce2b90 | 996.708 | 224.690 | 34.234 | 0.322593 | 默认参考 |
| `hysteria2-native-brutal-salamander` | mixed | 普通 | mihomo | 2ce2b90 | 983.349 | 206.803 | 37.980 | 1.726564 | Mihomo严格参考 |
| `hysteria2-native-brutal-salamander` | tcp | 普通 | mihomo | 2ce2b90 | 996.252 | 155.511 | 35.727 | N/A | 默认参考 |
| `hysteria2-native-brutal-salamander` | udp | 普通 | mihomo | 2ce2b90 | 994.772 | 222.794 | 37.051 | 0.511889 | 默认参考 |
| `hysteria2-native-hop` | mixed | 普通 | hysteria2 | 2ce2b90 | 998.902 | 198.209 | 34.254 | 0.208641 | 默认参考 |
| `hysteria2-native-hop` | tcp | 普通 | hysteria2 | 2ce2b90 | 996.243 | 124.147 | 35.684 | N/A | 默认参考 |
| `hysteria2-native-hop` | udp | 普通 | hysteria2 | 2ce2b90 | 981.579 | 206.016 | 34.383 | 1.837413 | Mihomo严格参考 |
| `hysteria2-native-hop-salamander` | mixed | 普通 | hysteria2 | 2ce2b90 | 998.645 | 211.362 | 35.102 | 0.259681 | 默认参考 |
| `hysteria2-native-hop-salamander` | tcp | 普通 | hysteria2 | 2ce2b90 | 996.278 | 153.954 | 35.586 | N/A | 默认参考 |
| `hysteria2-native-hop-salamander` | udp | 普通 | hysteria2 | 2ce2b90 | 988.349 | 213.756 | 35.359 | 1.159539 | Mihomo严格参考 |
| `hysteria2-native-mtls` | mixed | 普通 | mihomo | 2ce2b90 | 999.351 | 199.992 | 34.805 | 0.119040 | 默认参考 |
| `hysteria2-native-mtls` | tcp | 普通 | mihomo | 2ce2b90 | 998.297 | 124.656 | 35.484 | N/A | 默认参考 |
| `hysteria2-native-mtls` | udp | 普通 | mihomo | 2ce2b90 | 984.614 | 211.907 | 35.234 | 1.162819 | Mihomo严格参考 |
| `hysteria2-realm-https-h1` | mixed | 普通 | mihomo | 2ce2b90 | 998.652 | 217.639 | 35.188 | 0.257057 | 默认参考 |
| `hysteria2-realm-https-h1` | tcp | 普通 | mihomo | 2ce2b90 | 996.768 | 158.203 | 36.293 | N/A | 默认参考 |
| `hysteria2-realm-https-h1` | udp | 普通 | mihomo | 2ce2b90 | 996.713 | 222.232 | 34.496 | 0.060304 | 默认参考 |
| `masque-h3-l4proxy` | tcp | 普通 | masque | 2ce2b90 | 998.550 | 140.480 | 35.461 | N/A | 默认参考 |
| `masque-h3-l4proxy-dns` | tcp | 普通 | masque | 2ce2b90 | 998.375 | 139.660 | 36.211 | N/A | 默认参考 |
| `socks5` | mixed | 普通 | mihomo | 2ce2b90 | 999.940 | 137.447 | 29.367 | 0.000000 | 默认参考 |
| `socks5` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 42.494 | 29.379 | N/A | 默认参考 |
| `socks5` | udp | 普通 | mihomo | 2ce2b90 | 999.906 | 157.585 | 29.824 | 0.005840 | 默认参考 |
| `socks5-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.939 | 134.881 | 31.523 | 0.000928 | 默认参考 |
| `socks5-tls` | tcp | 普通 | mihomo | 2ce2b90 | 999.136 | 45.555 | 32.293 | N/A | 默认参考 |
| `socks5-tls` | udp | 普通 | mihomo | 2ce2b90 | 999.965 | 167.349 | 31.078 | 0.000000 | 默认参考 |
| `ss-rust-eih-aes128` | mixed | 普通 | shadowsocks-rust | 2ce2b90 | 990.202 | 150.054 | 31.516 | 1.811557 | Mihomo严格参考 |
| `ss-rust-eih-aes128` | tcp | 普通 | shadowsocks-rust | 2ce2b90 | 999.922 | 45.441 | 32.938 | N/A | 默认参考 |
| `ss-rust-eih-aes128` | udp | 普通 | shadowsocks-rust | 2ce2b90 | 916.464 | 184.021 | 30.906 | 8.350661 | Mihomo严格参考 |
| `ss-rust-eih-aes256` | mixed | 普通 | shadowsocks-rust | 2ce2b90 | 991.770 | 154.615 | 31.473 | 1.633828 | Mihomo严格参考 |
| `ss-rust-eih-aes256` | tcp | 普通 | shadowsocks-rust | 2ce2b90 | 999.896 | 44.835 | 32.492 | N/A | 默认参考 |
| `ss-rust-eih-aes256` | udp | 普通 | shadowsocks-rust | 2ce2b90 | 932.762 | 183.125 | 30.898 | 6.717953 | Mihomo严格参考 |
| `ss2022-obfs-http` | mixed | 普通 | mihomo | 2ce2b90 | 999.849 | 146.882 | 31.516 | 0.018912 | 默认参考 |
| `ss2022-obfs-http` | tcp | 普通 | mihomo | 2ce2b90 | 999.826 | 46.126 | 31.742 | N/A | 默认参考 |
| `ss2022-obfs-http` | udp | 普通 | mihomo | 2ce2b90 | 999.838 | 183.588 | 30.742 | 0.012960 | 默认参考 |
| `ss2022-obfs-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.933 | 157.297 | 30.934 | 0.000864 | 默认参考 |
| `ss2022-obfs-tls` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 46.513 | 31.957 | N/A | 默认参考 |
| `ss2022-obfs-tls` | udp | 普通 | mihomo | 2ce2b90 | 999.619 | 186.082 | 30.797 | 0.034624 | 默认参考 |
| `ss2022-v2ray-plugin-mux` | mixed | 普通 | mihomo | 2ce2b90 | 999.157 | 172.082 | 32.953 | 0.013728 | 默认参考 |
| `ss2022-v2ray-plugin-mux` | tcp | 普通 | mihomo | 2ce2b90 | 997.021 | 64.285 | 33.051 | N/A | 默认参考 |
| `ss2022-v2ray-plugin-mux` | udp | 普通 | mihomo | 2ce2b90 | 996.450 | 189.061 | 33.078 | 0.205761 | 默认参考 |
| `trojan` | mixed | 普通 | mihomo | 2ce2b90 | 999.929 | 165.625 | 31.934 | 0.000000 | 默认参考 |
| `trojan` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 46.517 | 32.758 | N/A | 默认参考 |
| `trojan` | udp | 普通 | mihomo | 2ce2b90 | 999.931 | 173.244 | 32.059 | 0.001552 | 默认参考 |
| `trojan-grpc-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.865 | 192.176 | 33.438 | 0.015744 | 默认参考 |
| `trojan-grpc-tls` | tcp | 普通 | mihomo | 2ce2b90 | 997.353 | 136.670 | 33.188 | N/A | 默认参考 |
| `trojan-httpupgrade-tls-fast` | mixed | 普通 | mihomo | 2ce2b90 | 999.941 | 156.164 | 32.031 | 0.000000 | 默认参考 |
| `trojan-httpupgrade-tls-fast` | tcp | 普通 | mihomo | 2ce2b90 | 999.424 | 45.062 | 32.973 | N/A | 默认参考 |
| `trojan-httpupgrade-tls-fast` | udp | 普通 | mihomo | 2ce2b90 | 999.951 | 170.217 | 32.148 | 0.000224 | 默认参考 |
| `trojan-httpupgrade-tls-normal` | mixed | 普通 | mihomo | 2ce2b90 | 999.939 | 159.308 | 32.426 | 0.000000 | 默认参考 |
| `trojan-httpupgrade-tls-normal` | tcp | 普通 | mihomo | 2ce2b90 | 998.603 | 47.482 | 32.855 | N/A | 默认参考 |
| `trojan-httpupgrade-tls-normal` | udp | 普通 | mihomo | 2ce2b90 | 999.946 | 172.888 | 32.402 | 0.000272 | 默认参考 |
| `trojan-tcp-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.826 | 149.142 | 32.633 | 0.024384 | 默认参考 |
| `trojan-tcp-tls` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 45.953 | 32.703 | N/A | 默认参考 |
| `trojan-ws-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 184.098 | 33.699 | 0.000000 | 默认参考 |
| `trojan-ws-tls` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 49.137 | 35.527 | N/A | 默认参考 |
| `trusttunnel-h2-tcp` | tcp | 普通 | mihomo | 2ce2b90 | 996.890 | 128.361 | 33.949 | N/A | 默认参考 |
| `trusttunnel-h2-udp-health` | mixed | 普通 | mihomo | 2ce2b90 | 999.930 | 212.104 | 34.855 | 0.000000 | 默认参考 |
| `trusttunnel-h2-udp-health` | tcp | 普通 | mihomo | 2ce2b90 | 996.287 | 116.460 | 34.469 | N/A | 默认参考 |
| `trusttunnel-h2-udp-health` | udp | 普通 | mihomo | 2ce2b90 | 999.916 | 230.093 | 35.262 | 0.000880 | 默认参考 |
| `trusttunnel-h3-tcp` | tcp | 普通 | mihomo | 2ce2b90 | 992.731 | 136.284 | 37.352 | N/A | 默认参考 |
| `trusttunnel-h3-udp-health` | mixed | 普通 | mihomo | 2ce2b90 | 999.863 | 217.138 | 38.164 | 0.014496 | 默认参考 |
| `trusttunnel-h3-udp-health` | tcp | 普通 | mihomo | 2ce2b90 | 997.904 | 136.288 | 38.176 | N/A | 默认参考 |
| `trusttunnel-h3-udp-health` | udp | 普通 | mihomo | 2ce2b90 | 999.727 | 245.674 | 37.289 | 0.021856 | 默认参考 |
| `vless` | mixed | 普通 | mihomo | 3fdee46 | 999.944 | 150.394 | 29.754 | 0.000000 | 默认参考 |
| `vless` | tcp | 普通 | mihomo | 3fdee46 | 999.712 | 40.959 | 30.117 | N/A | 默认参考 |
| `vless` | udp | 普通 | mihomo | 3fdee46 | 999.946 | 164.485 | 30.086 | 0.000544 | 默认参考 |
| `vless-caddy-xhttp-h3-mtls` | mixed | 普通 | xray | e774a51 | 999.922 | 187.464 | 39.168 | 0.000000 | 默认参考 |
| `vless-caddy-xhttp-h3-mtls` | tcp | 普通 | xray | e774a51 | 997.336 | 120.496 | 40.281 | N/A | 默认参考 |
| `vless-caddy-xhttp-h3-mtls` | udp | 普通 | xray | e774a51 | 997.800 | 195.076 | 40.531 | 0.000000 | 默认参考 |
| `vless-encryption-native-0rtt` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 183.097 | 31.773 | 0.000000 | 默认参考 |
| `vless-encryption-native-0rtt` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 54.050 | 31.801 | N/A | 默认参考 |
| `vless-encryption-native-0rtt` | udp | 普通 | mihomo | 2ce2b90 | 999.915 | 195.579 | 31.695 | 0.003968 | 默认参考 |
| `vless-encryption-native-0rtt-vision` | mixed | 普通 | mihomo | 2ce2b90 | 999.944 | 184.623 | 31.512 | 0.000000 | 默认参考 |
| `vless-encryption-native-0rtt-vision` | tcp | 普通 | mihomo | 2ce2b90 | 995.876 | 60.186 | 32.367 | N/A | 默认参考 |
| `vless-encryption-native-0rtt-vision` | tcp | TLS1.3 | mihomo | 2ce2b90 | 998.926 | 49.540 | 32.234 | N/A | 默认参考 |
| `vless-encryption-native-0rtt-vision` | udp | 普通 | mihomo | 2ce2b90 | 997.900 | 193.665 | 31.883 | 0.010192 | 默认参考 |
| `vless-encryption-native-1rtt` | mixed | 普通 | mihomo | 2ce2b90 | 999.946 | 173.131 | 31.750 | 0.000000 | 默认参考 |
| `vless-encryption-native-1rtt` | tcp | 普通 | mihomo | 2ce2b90 | 999.878 | 53.293 | 31.812 | N/A | 默认参考 |
| `vless-encryption-native-1rtt` | udp | 普通 | mihomo | 2ce2b90 | 991.459 | 181.393 | 32.082 | 0.053696 | 默认参考 |
| `vless-encryption-native-1rtt-vision` | mixed | 普通 | mihomo | 2ce2b90 | 999.947 | 181.260 | 32.949 | 0.000000 | 默认参考 |
| `vless-encryption-native-1rtt-vision` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 53.135 | 32.023 | N/A | 默认参考 |
| `vless-encryption-native-1rtt-vision` | tcp | TLS1.3 | mihomo | 2ce2b90 | 999.922 | 44.533 | 32.230 | N/A | 默认参考 |
| `vless-encryption-native-1rtt-vision` | udp | 普通 | mihomo | 2ce2b90 | 998.949 | 191.630 | 31.859 | 0.003088 | 默认参考 |
| `vless-encryption-random-0rtt` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 188.062 | 31.871 | 0.000000 | 默认参考 |
| `vless-encryption-random-0rtt` | tcp | 普通 | mihomo | 2ce2b90 | 999.695 | 54.280 | 31.621 | N/A | 默认参考 |
| `vless-encryption-random-0rtt` | udp | 普通 | mihomo | 2ce2b90 | 999.925 | 195.838 | 31.664 | 0.000976 | 默认参考 |
| `vless-encryption-random-0rtt-vision` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 185.047 | 32.051 | 0.000000 | 默认参考 |
| `vless-encryption-random-0rtt-vision` | tcp | 普通 | mihomo | 2ce2b90 | 999.774 | 54.947 | 32.137 | N/A | 默认参考 |
| `vless-encryption-random-0rtt-vision` | tcp | TLS1.3 | mihomo | 2ce2b90 | 999.608 | 49.017 | 32.133 | N/A | 默认参考 |
| `vless-encryption-random-0rtt-vision` | udp | 普通 | mihomo | 2ce2b90 | 999.914 | 196.467 | 31.879 | 0.002896 | 默认参考 |
| `vless-encryption-random-1rtt` | mixed | 普通 | mihomo | 2ce2b90 | 999.938 | 180.662 | 31.766 | 0.000000 | 默认参考 |
| `vless-encryption-random-1rtt` | tcp | 普通 | mihomo | 2ce2b90 | 999.590 | 53.692 | 31.965 | N/A | 默认参考 |
| `vless-encryption-random-1rtt` | udp | 普通 | mihomo | 2ce2b90 | 999.924 | 194.921 | 31.836 | 0.003472 | 默认参考 |
| `vless-encryption-random-1rtt-vision` | mixed | 普通 | mihomo | 2ce2b90 | 999.934 | 187.320 | 32.094 | 0.000000 | 默认参考 |
| `vless-encryption-random-1rtt-vision` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 53.465 | 32.047 | N/A | 默认参考 |
| `vless-encryption-random-1rtt-vision` | tcp | TLS1.3 | mihomo | 2ce2b90 | 999.922 | 46.345 | 32.211 | N/A | 默认参考 |
| `vless-encryption-random-1rtt-vision` | udp | 普通 | mihomo | 2ce2b90 | 999.054 | 201.293 | 32.094 | 0.005744 | 默认参考 |
| `vless-encryption-xorpub-0rtt` | mixed | 普通 | mihomo | 2ce2b90 | 999.936 | 187.222 | 31.742 | 0.000000 | 默认参考 |
| `vless-encryption-xorpub-0rtt` | tcp | 普通 | mihomo | 2ce2b90 | 999.791 | 58.248 | 31.574 | N/A | 默认参考 |
| `vless-encryption-xorpub-0rtt` | udp | 普通 | mihomo | 2ce2b90 | 999.422 | 193.274 | 31.828 | 0.004528 | 默认参考 |
| `vless-encryption-xorpub-0rtt-vision` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 187.100 | 31.742 | 0.000000 | 默认参考 |
| `vless-encryption-xorpub-0rtt-vision` | tcp | 普通 | mihomo | 2ce2b90 | 999.642 | 54.043 | 32.422 | N/A | 默认参考 |
| `vless-encryption-xorpub-0rtt-vision` | tcp | TLS1.3 | mihomo | 2ce2b90 | 999.922 | 45.389 | 32.371 | N/A | 默认参考 |
| `vless-encryption-xorpub-0rtt-vision` | udp | 普通 | mihomo | 2ce2b90 | 999.874 | 194.094 | 31.914 | 0.005696 | 默认参考 |
| `vless-encryption-xorpub-1rtt` | mixed | 普通 | mihomo | 2ce2b90 | 999.944 | 179.972 | 31.797 | 0.000000 | 默认参考 |
| `vless-encryption-xorpub-1rtt` | tcp | 普通 | mihomo | 2ce2b90 | 998.734 | 63.267 | 32.234 | N/A | 默认参考 |
| `vless-encryption-xorpub-1rtt` | udp | 普通 | mihomo | 2ce2b90 | 988.892 | 183.584 | 31.883 | 0.011584 | 默认参考 |
| `vless-encryption-xorpub-1rtt-vision` | mixed | 普通 | mihomo | 2ce2b90 | 999.947 | 182.539 | 31.984 | 0.000000 | 默认参考 |
| `vless-encryption-xorpub-1rtt-vision` | tcp | 普通 | mihomo | 2ce2b90 | 999.573 | 53.238 | 31.672 | N/A | 默认参考 |
| `vless-encryption-xorpub-1rtt-vision` | tcp | TLS1.3 | mihomo | 2ce2b90 | 999.922 | 44.940 | 32.242 | N/A | 默认参考 |
| `vless-encryption-xorpub-1rtt-vision` | udp | 普通 | mihomo | 2ce2b90 | 999.854 | 189.929 | 31.789 | 0.008896 | 默认参考 |
| `vless-grpc-jls` | mixed | 普通 | mihomo | 2ce2b90 | 999.941 | 205.258 | 33.461 | 0.000000 | 默认参考 |
| `vless-grpc-jls` | tcp | 普通 | mihomo | 2ce2b90 | 995.824 | 128.676 | 33.543 | N/A | 默认参考 |
| `vless-grpc-plain` | mixed | 普通 | mihomo | 2ce2b90 | 999.946 | 186.882 | 31.359 | 0.000000 | 默认参考 |
| `vless-grpc-plain` | tcp | 普通 | mihomo | 2ce2b90 | 997.493 | 115.300 | 32.168 | N/A | 默认参考 |
| `vless-grpc-reality` | mixed | 普通 | mihomo | 2ce2b90 | 999.940 | 201.714 | 33.715 | 0.000000 | 默认参考 |
| `vless-grpc-reality` | tcp | 普通 | mihomo | 2ce2b90 | 998.795 | 139.322 | 33.445 | N/A | 默认参考 |
| `vless-grpc-tls` | tcp | 普通 | mihomo | 2ce2b90 | 997.248 | 134.625 | 33.137 | N/A | 默认参考 |
| `vless-httpupgrade-jls-fast` | mixed | 普通 | mihomo | 2ce2b90 | 999.945 | 165.811 | 31.742 | 0.000000 | 默认参考 |
| `vless-httpupgrade-jls-fast` | tcp | 普通 | mihomo | 2ce2b90 | 999.843 | 44.562 | 32.051 | N/A | 默认参考 |
| `vless-httpupgrade-jls-fast` | udp | 普通 | mihomo | 2ce2b90 | 999.965 | 186.067 | 31.895 | 0.000000 | 默认参考 |
| `vless-httpupgrade-jls-normal` | mixed | 普通 | mihomo | 2ce2b90 | 999.947 | 163.590 | 31.980 | 0.000000 | 默认参考 |
| `vless-httpupgrade-jls-normal` | tcp | 普通 | mihomo | 2ce2b90 | 999.913 | 45.122 | 32.316 | N/A | 默认参考 |
| `vless-httpupgrade-jls-normal` | udp | 普通 | mihomo | 2ce2b90 | 999.929 | 183.064 | 32.082 | 0.000272 | 默认参考 |
| `vless-httpupgrade-plain-fast` | mixed | 普通 | mihomo | 2ce2b90 | 999.940 | 141.416 | 29.828 | 0.000000 | 默认参考 |
| `vless-httpupgrade-plain-fast` | tcp | 普通 | mihomo | 2ce2b90 | 998.105 | 40.533 | 29.930 | N/A | 默认参考 |
| `vless-httpupgrade-plain-fast` | udp | 普通 | mihomo | 2ce2b90 | 999.962 | 156.868 | 30.016 | 0.000016 | 默认参考 |
| `vless-httpupgrade-plain-normal` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 139.538 | 29.793 | 0.000000 | 默认参考 |
| `vless-httpupgrade-plain-normal` | tcp | 普通 | mihomo | 2ce2b90 | 998.751 | 41.620 | 29.750 | N/A | 默认参考 |
| `vless-httpupgrade-plain-normal` | udp | 普通 | mihomo | 2ce2b90 | 999.943 | 154.037 | 30.254 | 0.000112 | 默认参考 |
| `vless-httpupgrade-tls-fast` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 159.308 | 32.473 | 0.000000 | 默认参考 |
| `vless-httpupgrade-tls-fast` | tcp | 普通 | mihomo | 2ce2b90 | 999.459 | 45.262 | 32.762 | N/A | 默认参考 |
| `vless-httpupgrade-tls-fast` | udp | 普通 | mihomo | 2ce2b90 | 999.947 | 169.785 | 32.000 | 0.000224 | 默认参考 |
| `vless-httpupgrade-tls-normal` | mixed | 普通 | mihomo | 2ce2b90 | 999.947 | 158.702 | 31.957 | 0.000000 | 默认参考 |
| `vless-httpupgrade-tls-normal` | tcp | 普通 | mihomo | 2ce2b90 | 998.541 | 46.167 | 32.691 | N/A | 默认参考 |
| `vless-httpupgrade-tls-normal` | udp | 普通 | mihomo | 2ce2b90 | 999.952 | 184.790 | 31.957 | 0.000000 | 默认参考 |
| `vless-tcp-jls` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 161.250 | 31.922 | 0.000000 | 默认参考 |
| `vless-tcp-jls` | tcp | 普通 | mihomo | 2ce2b90 | 999.852 | 44.653 | 32.113 | N/A | 默认参考 |
| `vless-tcp-jls` | udp | 普通 | mihomo | 2ce2b90 | 999.958 | 176.348 | 32.047 | 0.000096 | 默认参考 |
| `vless-tcp-none` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 144.149 | 27.176 | 0.000000 | 默认参考 |
| `vless-tcp-none` | tcp | 普通 | mihomo | 2ce2b90 | 999.835 | 40.418 | 29.691 | N/A | 默认参考 |
| `vless-tcp-none` | udp | 普通 | mihomo | 2ce2b90 | 999.949 | 170.657 | 24.496 | 0.000000 | 默认参考 |
| `vless-tcp-packetaddr` | mixed | 普通 | mihomo | 2ce2b90 | 999.944 | 164.868 | 29.539 | 0.000000 | 默认参考 |
| `vless-tcp-packetaddr` | tcp | 普通 | mihomo | 2ce2b90 | 999.503 | 40.732 | 29.758 | N/A | 默认参考 |
| `vless-tcp-packetaddr` | udp | 普通 | mihomo | 2ce2b90 | 999.929 | 194.906 | 30.621 | 0.000000 | 默认参考 |
| `vless-tcp-plain` | tcp | 普通 | mihomo | 2ce2b90 | 998.952 | 40.955 | 29.648 | N/A | 默认参考 |
| `vless-tcp-plain-mptcp` | mixed | 普通 | mihomo | 2ce2b90 | 999.936 | 148.286 | 29.988 | 0.001568 | 默认参考 |
| `vless-tcp-plain-mptcp` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 41.551 | 29.836 | N/A | 默认参考 |
| `vless-tcp-plain-mptcp` | udp | 普通 | mihomo | 2ce2b90 | 999.825 | 159.581 | 30.312 | 0.012128 | 默认参考 |
| `vless-tcp-reality` | mixed | 普通 | mihomo | 2ce2b90 | 999.944 | 162.285 | 31.293 | 0.000000 | 默认参考 |
| `vless-tcp-reality` | tcp | 普通 | mihomo | 2ce2b90 | 999.843 | 44.416 | 32.266 | N/A | 默认参考 |
| `vless-tcp-reality` | udp | 普通 | mihomo | 2ce2b90 | 999.946 | 177.103 | 32.035 | 0.000848 | 默认参考 |
| `vless-tcp-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.945 | 161.671 | 31.496 | 0.000000 | 默认参考 |
| `vless-tcp-tls` | udp | 普通 | mihomo | 2ce2b90 | 999.952 | 173.747 | 31.625 | 0.000448 | 默认参考 |
| `vless-tcp-tls-h2mux` | tcp | 普通 | mihomo | 2ce2b90 | 995.492 | 116.542 | 33.266 | N/A | 默认参考 |
| `vless-tcp-tls-h2mux` | udp | 普通 | mihomo | 2ce2b90 | 599.105 | 185.394 | 36.215 | 39.840150 | Mihomo严格参考 |
| `vless-tcp-tls-h2mux-brutal` | mixed | 普通 | mihomo | 2ce2b90 | 999.932 | 208.947 | 33.508 | 0.000000 | 默认参考 |
| `vless-tcp-tls-h2mux-brutal` | tcp | 普通 | mihomo | 2ce2b90 | 999.074 | 114.070 | 33.148 | N/A | 默认参考 |
| `vless-tcp-tls-h2mux-brutal` | udp | 普通 | mihomo | 2ce2b90 | 629.436 | 187.925 | 36.102 | 36.811758 | Mihomo严格参考 |
| `vless-tcp-tls-yamux` | mixed | 普通 | mihomo | 2ce2b90 | 998.747 | 169.782 | 34.758 | 0.064352 | 默认参考 |
| `vless-tcp-tls-yamux` | tcp | 普通 | mihomo | 2ce2b90 | 999.712 | 53.585 | 35.121 | N/A | 默认参考 |
| `vless-tcp-tls-yamux` | udp | 普通 | mihomo | 2ce2b90 | 999.424 | 200.801 | 34.602 | 0.053536 | 默认参考 |
| `vless-v2ray-h2-plain` | mixed | 普通 | v2ray | 3fdee46 | 999.942 | 192.609 | 31.996 | 0.000000 | 默认参考 |
| `vless-v2ray-h2-plain` | tcp | 普通 | v2ray | 3fdee46 | 999.922 | 53.484 | 33.055 | N/A | 默认参考 |
| `vless-v2ray-h2-plain` | udp | 普通 | v2ray | 3fdee46 | 999.921 | 215.338 | 32.266 | 0.000000 | 默认参考 |
| `vless-v2ray-h2-tls` | mixed | 普通 | v2ray | 3fdee46 | 999.941 | 209.105 | 34.285 | 0.000000 | 默认参考 |
| `vless-v2ray-h2-tls` | tcp | 普通 | v2ray | 3fdee46 | 994.994 | 137.660 | 38.465 | N/A | 默认参考 |
| `vless-v2ray-h2-tls` | udp | 普通 | v2ray | 3fdee46 | 999.857 | 235.707 | 34.691 | 0.000000 | 默认参考 |
| `vless-v2ray-ws-ed-header` | mixed | 普通 | v2ray | 3fdee46 | 999.941 | 153.567 | 28.520 | 0.000000 | 默认参考 |
| `vless-v2ray-ws-ed-header` | tcp | 普通 | v2ray | 3fdee46 | 999.669 | 47.558 | 30.887 | N/A | 默认参考 |
| `vless-v2ray-ws-ed-header` | udp | 普通 | v2ray | 3fdee46 | 999.943 | 190.767 | 25.699 | 0.000000 | Mihomo严格参考 |
| `vless-v2ray-ws-ed-path` | mixed | 普通 | v2ray | 3fdee46 | 999.945 | 155.705 | 28.445 | 0.000000 | 默认参考 |
| `vless-v2ray-ws-ed-path` | tcp | 普通 | v2ray | 3fdee46 | 999.354 | 47.846 | 30.969 | N/A | 默认参考 |
| `vless-v2ray-ws-ed-path` | udp | 普通 | v2ray | 3fdee46 | 999.942 | 187.590 | 26.023 | 0.000000 | 默认参考 |
| `vless-vision-reality` | mixed | 普通 | mihomo | 2ce2b90 | 999.951 | 172.421 | 31.625 | 0.000000 | 默认参考 |
| `vless-vision-reality` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 45.880 | 31.879 | N/A | 默认参考 |
| `vless-vision-reality` | tcp | TLS1.3 | mihomo | 2ce2b90 | 999.922 | 42.008 | 32.199 | N/A | 默认参考 |
| `vless-vision-reality` | udp | 普通 | mihomo | 2ce2b90 | 999.940 | 191.290 | 32.031 | 0.000720 | 默认参考 |
| `vless-vision-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 165.272 | 32.523 | 0.001184 | 默认参考 |
| `vless-vision-tls` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 49.589 | 33.090 | N/A | 默认参考 |
| `vless-vision-tls` | tcp | TLS1.3 | mihomo | 2ce2b90 | 999.922 | 43.878 | 32.000 | N/A | 默认参考 |
| `vless-vision-tls` | udp | 普通 | mihomo | 2ce2b90 | 999.891 | 180.759 | 32.621 | 0.005104 | 默认参考 |
| `vless-ws-jls` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 188.732 | 33.004 | 0.000000 | 默认参考 |
| `vless-ws-jls` | tcp | 普通 | mihomo | 2ce2b90 | 998.839 | 47.448 | 33.832 | N/A | 默认参考 |
| `vless-ws-jls` | udp | 普通 | mihomo | 2ce2b90 | 999.941 | 208.438 | 33.160 | 0.000976 | 默认参考 |
| `vless-ws-plain` | mixed | 普通 | mihomo | 2ce2b90 | 999.948 | 165.905 | 31.176 | 0.000000 | 默认参考 |
| `vless-ws-plain` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 44.911 | 31.734 | N/A | 默认参考 |
| `vless-ws-plain` | udp | 普通 | mihomo | 2ce2b90 | 999.932 | 174.935 | 31.242 | 0.000512 | 默认参考 |
| `vless-ws-plain-ed4096` | tcp | 普通 | mihomo | 2ce2b90 | 999.826 | 43.363 | 31.859 | N/A | 默认参考 |
| `vless-ws-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.938 | 177.486 | 33.738 | 0.000000 | 默认参考 |
| `vless-ws-tls` | tcp | 普通 | mihomo | 2ce2b90 | 999.013 | 48.140 | 34.949 | N/A | 默认参考 |
| `vless-ws-tls` | udp | 普通 | mihomo | 2ce2b90 | 999.949 | 192.098 | 33.090 | 0.000272 | 默认参考 |
| `vless-xhttp-h1-jls-packet-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.924 | 137.416 | 41.289 | 0.000672 | 默认参考 |
| `vless-xhttp-h1-jls-packet-up` | tcp | 普通 | mihomo | 2ce2b90 | 998.611 | 48.386 | 41.098 | N/A | 默认参考 |
| `vless-xhttp-h1-jls-packet-up` | udp | 普通 | mihomo | 2ce2b90 | 999.826 | 176.121 | 41.914 | 0.000768 | 默认参考 |
| `vless-xhttp-h1-jls-packet-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.914 | 144.581 | 41.164 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-jls-packet-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 999.756 | 47.682 | 41.445 | N/A | 默认参考 |
| `vless-xhttp-h1-jls-packet-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.859 | 176.151 | 41.852 | 0.001520 | 默认参考 |
| `vless-xhttp-h1-jls-stream-one` | mixed | 普通 | mihomo | 3fdee46 | 999.939 | 196.845 | 35.957 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-jls-stream-one` | tcp | 普通 | mihomo | 3fdee46 | 999.503 | 53.169 | 35.668 | N/A | 默认参考 |
| `vless-xhttp-h1-jls-stream-one` | udp | 普通 | mihomo | 3fdee46 | 999.769 | 217.016 | 35.961 | 0.015152 | 默认参考 |
| `vless-xhttp-h1-jls-stream-up` | mixed | 普通 | mihomo | 3fdee46 | 999.942 | 211.429 | 37.801 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-jls-stream-up` | tcp | 普通 | mihomo | 3fdee46 | 999.669 | 54.020 | 37.480 | N/A | 默认参考 |
| `vless-xhttp-h1-jls-stream-up` | udp | 普通 | mihomo | 3fdee46 | 999.528 | 222.143 | 38.141 | 0.034784 | 默认参考 |
| `vless-xhttp-h1-jls-stream-up-download` | mixed | 普通 | mihomo | 3fdee46 | 999.935 | 206.039 | 38.168 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-jls-stream-up-download` | tcp | 普通 | mihomo | 3fdee46 | 999.765 | 54.468 | 37.664 | N/A | 默认参考 |
| `vless-xhttp-h1-jls-stream-up-download` | udp | 普通 | mihomo | 3fdee46 | 999.797 | 220.085 | 38.398 | 0.011280 | 默认参考 |
| `vless-xhttp-h1-plain-packet-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.925 | 120.507 | 39.148 | 0.000288 | 默认参考 |
| `vless-xhttp-h1-plain-packet-up` | tcp | 普通 | mihomo | 2ce2b90 | 999.704 | 43.770 | 38.949 | N/A | 默认参考 |
| `vless-xhttp-h1-plain-packet-up` | udp | 普通 | mihomo | 2ce2b90 | 999.823 | 161.473 | 39.152 | 0.008304 | 默认参考 |
| `vless-xhttp-h1-plain-packet-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.912 | 129.557 | 39.008 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-plain-packet-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 999.573 | 44.447 | 39.320 | N/A | 默认参考 |
| `vless-xhttp-h1-plain-packet-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.864 | 161.322 | 39.227 | 0.004096 | 默认参考 |
| `vless-xhttp-h1-plain-stream-one` | mixed | 普通 | mihomo | 3fdee46 | 999.941 | 179.013 | 34.219 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-plain-stream-one` | tcp | 普通 | mihomo | 3fdee46 | 999.922 | 47.287 | 34.113 | N/A | 默认参考 |
| `vless-xhttp-h1-plain-stream-one` | udp | 普通 | mihomo | 3fdee46 | 999.789 | 191.264 | 35.027 | 0.012384 | 默认参考 |
| `vless-xhttp-h1-plain-stream-up` | mixed | 普通 | mihomo | 3fdee46 | 999.941 | 185.005 | 35.645 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-plain-stream-up` | tcp | 普通 | mihomo | 3fdee46 | 999.765 | 47.157 | 35.637 | N/A | 默认参考 |
| `vless-xhttp-h1-plain-stream-up` | udp | 普通 | mihomo | 3fdee46 | 999.674 | 189.890 | 36.023 | 0.026512 | 默认参考 |
| `vless-xhttp-h1-plain-stream-up-download` | mixed | 普通 | mihomo | 3fdee46 | 999.943 | 182.294 | 35.672 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-plain-stream-up-download` | tcp | 普通 | mihomo | 3fdee46 | 999.922 | 48.965 | 35.254 | N/A | 默认参考 |
| `vless-xhttp-h1-plain-stream-up-download` | udp | 普通 | mihomo | 3fdee46 | 999.803 | 190.905 | 36.016 | 0.013520 | 默认参考 |
| `vless-xhttp-h1-reality-packet-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.927 | 146.800 | 41.031 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-reality-packet-up` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 48.264 | 40.816 | N/A | 默认参考 |
| `vless-xhttp-h1-reality-packet-up` | udp | 普通 | mihomo | 2ce2b90 | 999.824 | 177.682 | 41.430 | 0.007600 | 默认参考 |
| `vless-xhttp-h1-reality-packet-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.927 | 146.731 | 41.613 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-reality-packet-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 999.800 | 46.912 | 40.969 | N/A | 默认参考 |
| `vless-xhttp-h1-reality-packet-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.915 | 176.834 | 41.590 | 0.000976 | 默认参考 |
| `vless-xhttp-h1-reality-stream-one` | mixed | 普通 | mihomo | 3fdee46 | 999.921 | 190.481 | 35.551 | 0.000672 | 默认参考 |
| `vless-xhttp-h1-reality-stream-one` | tcp | 普通 | mihomo | 3fdee46 | 999.529 | 53.272 | 35.758 | N/A | 默认参考 |
| `vless-xhttp-h1-reality-stream-one` | udp | 普通 | mihomo | 3fdee46 | 999.716 | 215.731 | 35.785 | 0.020096 | 默认参考 |
| `vless-xhttp-h1-reality-stream-up` | mixed | 普通 | mihomo | 3fdee46 | 999.941 | 211.682 | 37.133 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-reality-stream-up` | tcp | 普通 | mihomo | 3fdee46 | 999.808 | 53.764 | 37.410 | N/A | 默认参考 |
| `vless-xhttp-h1-reality-stream-up` | udp | 普通 | mihomo | 3fdee46 | 999.836 | 225.022 | 37.617 | 0.009120 | 默认参考 |
| `vless-xhttp-h1-reality-stream-up-download` | mixed | 普通 | mihomo | 3fdee46 | 999.945 | 206.111 | 37.922 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-reality-stream-up-download` | tcp | 普通 | mihomo | 3fdee46 | 999.319 | 54.399 | 37.711 | N/A | 默认参考 |
| `vless-xhttp-h1-reality-stream-up-download` | udp | 普通 | mihomo | 3fdee46 | 999.824 | 223.844 | 37.836 | 0.005472 | 默认参考 |
| `vless-xhttp-h1-tls-packet-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.916 | 139.477 | 42.125 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-tls-packet-up` | tcp | 普通 | mihomo | 2ce2b90 | 998.349 | 48.195 | 42.199 | N/A | 默认参考 |
| `vless-xhttp-h1-tls-packet-up` | udp | 普通 | mihomo | 2ce2b90 | 999.825 | 172.402 | 41.258 | 0.004384 | 默认参考 |
| `vless-xhttp-h1-tls-packet-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.924 | 139.827 | 42.402 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-tls-packet-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 997.598 | 48.541 | 42.516 | N/A | 默认参考 |
| `vless-xhttp-h1-tls-packet-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.883 | 171.327 | 41.453 | 0.001296 | 默认参考 |
| `vless-xhttp-h1-tls-stream-one` | mixed | 普通 | mihomo | 3fdee46 | 999.950 | 197.100 | 36.316 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-tls-stream-one` | tcp | 普通 | mihomo | 3fdee46 | 999.441 | 52.960 | 36.809 | N/A | 默认参考 |
| `vless-xhttp-h1-tls-stream-one` | udp | 普通 | mihomo | 3fdee46 | 999.540 | 206.648 | 36.762 | 0.039808 | 默认参考 |
| `vless-xhttp-h1-tls-stream-up` | mixed | 普通 | mihomo | 3fdee46 | 999.940 | 203.000 | 38.211 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-tls-stream-up` | tcp | 普通 | mihomo | 3fdee46 | 999.660 | 53.042 | 39.078 | N/A | 默认参考 |
| `vless-xhttp-h1-tls-stream-up` | udp | 普通 | mihomo | 3fdee46 | 999.761 | 214.341 | 38.809 | 0.016352 | 默认参考 |
| `vless-xhttp-h1-tls-stream-up-download` | mixed | 普通 | mihomo | 3fdee46 | 999.946 | 203.772 | 38.242 | 0.000000 | 默认参考 |
| `vless-xhttp-h1-tls-stream-up-download` | tcp | 普通 | mihomo | 3fdee46 | 999.870 | 53.284 | 38.699 | N/A | 默认参考 |
| `vless-xhttp-h1-tls-stream-up-download` | udp | 普通 | mihomo | 3fdee46 | 999.845 | 213.712 | 38.656 | 0.007840 | 默认参考 |
| `vless-xhttp-h2-jls-packet-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.926 | 144.833 | 40.348 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-jls-packet-up` | tcp | 普通 | mihomo | 2ce2b90 | 999.730 | 51.087 | 41.344 | N/A | 默认参考 |
| `vless-xhttp-h2-jls-packet-up` | udp | 普通 | mihomo | 2ce2b90 | 999.876 | 169.169 | 40.027 | 0.002816 | 默认参考 |
| `vless-xhttp-h2-jls-packet-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.931 | 145.109 | 38.383 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-jls-packet-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 997.869 | 80.551 | 39.391 | N/A | 默认参考 |
| `vless-xhttp-h2-jls-packet-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.876 | 168.905 | 38.797 | 0.002064 | 默认参考 |
| `vless-xhttp-h2-jls-stream-one` | mixed | 普通 | mihomo | 2ce2b90 | 999.945 | 206.476 | 37.215 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-jls-stream-one` | tcp | 普通 | mihomo | 2ce2b90 | 996.654 | 123.320 | 38.227 | N/A | 默认参考 |
| `vless-xhttp-h2-jls-stream-one` | udp | 普通 | mihomo | 2ce2b90 | 999.909 | 214.773 | 39.910 | 0.002480 | 默认参考 |
| `vless-xhttp-h2-jls-stream-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.945 | 211.264 | 36.629 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-jls-stream-up` | tcp | 普通 | mihomo | 2ce2b90 | 996.776 | 118.537 | 38.453 | N/A | 默认参考 |
| `vless-xhttp-h2-jls-stream-up` | udp | 普通 | mihomo | 2ce2b90 | 999.844 | 217.003 | 39.145 | 0.001104 | 默认参考 |
| `vless-xhttp-h2-jls-stream-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.934 | 209.315 | 39.660 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-jls-stream-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 997.624 | 126.032 | 40.809 | N/A | 默认参考 |
| `vless-xhttp-h2-jls-stream-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.910 | 216.160 | 42.266 | 0.000016 | 默认参考 |
| `vless-xhttp-h2-plain-packet-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.934 | 129.423 | 38.324 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-plain-packet-up` | tcp | 普通 | mihomo | 2ce2b90 | 999.546 | 45.827 | 38.539 | N/A | 默认参考 |
| `vless-xhttp-h2-plain-packet-up` | udp | 普通 | mihomo | 2ce2b90 | 999.917 | 159.426 | 37.918 | 0.001184 | 默认参考 |
| `vless-xhttp-h2-plain-packet-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.928 | 130.375 | 40.477 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-plain-packet-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 999.573 | 45.631 | 40.738 | N/A | 默认参考 |
| `vless-xhttp-h2-plain-packet-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.886 | 159.218 | 40.391 | 0.001488 | 默认参考 |
| `vless-xhttp-h2-plain-stream-one` | mixed | 普通 | mihomo | 2ce2b90 | 999.934 | 187.135 | 34.672 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-plain-stream-one` | tcp | 普通 | mihomo | 2ce2b90 | 996.899 | 97.363 | 36.488 | N/A | 默认参考 |
| `vless-xhttp-h2-plain-stream-one` | udp | 普通 | mihomo | 2ce2b90 | 999.893 | 193.048 | 36.836 | 0.003024 | 默认参考 |
| `vless-xhttp-h2-plain-stream-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 186.904 | 34.707 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-plain-stream-up` | tcp | 普通 | mihomo | 2ce2b90 | 999.005 | 58.145 | 35.195 | N/A | 默认参考 |
| `vless-xhttp-h2-plain-stream-up` | udp | 普通 | mihomo | 2ce2b90 | 999.813 | 194.487 | 37.758 | 0.007136 | 默认参考 |
| `vless-xhttp-h2-plain-stream-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.865 | 186.893 | 37.129 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-plain-stream-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 998.445 | 77.079 | 37.934 | N/A | 默认参考 |
| `vless-xhttp-h2-plain-stream-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.890 | 191.182 | 39.004 | 0.004464 | 默认参考 |
| `vless-xhttp-h2-reality-packet-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.922 | 142.073 | 39.676 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-reality-packet-up` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 48.730 | 39.875 | N/A | 默认参考 |
| `vless-xhttp-h2-reality-packet-up` | udp | 普通 | mihomo | 2ce2b90 | 999.843 | 174.588 | 39.629 | 0.006208 | 默认参考 |
| `vless-xhttp-h2-reality-packet-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.923 | 140.371 | 38.844 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-reality-packet-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 998.297 | 78.267 | 39.406 | N/A | 默认参考 |
| `vless-xhttp-h2-reality-packet-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.903 | 172.950 | 38.262 | 0.000800 | 默认参考 |
| `vless-xhttp-h2-reality-stream-one` | mixed | 普通 | mihomo | 2ce2b90 | 999.947 | 207.420 | 36.734 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-reality-stream-one` | tcp | 普通 | mihomo | 2ce2b90 | 997.423 | 123.961 | 37.668 | N/A | 默认参考 |
| `vless-xhttp-h2-reality-stream-one` | udp | 普通 | mihomo | 2ce2b90 | 999.752 | 215.289 | 39.488 | 0.002960 | 默认参考 |
| `vless-xhttp-h2-reality-stream-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.950 | 205.352 | 37.168 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-reality-stream-up` | tcp | 普通 | mihomo | 2ce2b90 | 998.498 | 126.082 | 38.535 | N/A | 默认参考 |
| `vless-xhttp-h2-reality-stream-up` | udp | 普通 | mihomo | 2ce2b90 | 999.784 | 217.591 | 39.582 | 0.012288 | 默认参考 |
| `vless-xhttp-h2-reality-stream-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.937 | 209.119 | 39.082 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-reality-stream-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 996.916 | 127.486 | 40.668 | N/A | 默认参考 |
| `vless-xhttp-h2-reality-stream-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.942 | 221.669 | 42.109 | 0.000560 | 默认参考 |
| `vless-xhttp-h2-tls-packet-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.925 | 135.794 | 39.973 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-tls-packet-up` | udp | 普通 | mihomo | 2ce2b90 | 999.886 | 174.043 | 39.316 | 0.001104 | 默认参考 |
| `vless-xhttp-h2-tls-packet-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.930 | 141.921 | 37.715 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-tls-packet-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 999.634 | 84.434 | 39.125 | N/A | 默认参考 |
| `vless-xhttp-h2-tls-packet-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.888 | 165.531 | 38.086 | 0.003072 | 默认参考 |
| `vless-xhttp-h2-tls-stream-one` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 201.399 | 36.781 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-tls-stream-one` | tcp | 普通 | mihomo | 2ce2b90 | 997.030 | 124.225 | 38.305 | N/A | 默认参考 |
| `vless-xhttp-h2-tls-stream-one` | udp | 普通 | mihomo | 2ce2b90 | 999.886 | 209.459 | 38.949 | 0.003488 | 默认参考 |
| `vless-xhttp-h2-tls-stream-up` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 199.669 | 36.656 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-tls-stream-up` | tcp | 普通 | mihomo | 2ce2b90 | 997.624 | 126.565 | 38.672 | N/A | 默认参考 |
| `vless-xhttp-h2-tls-stream-up` | udp | 普通 | mihomo | 2ce2b90 | 999.853 | 213.499 | 38.051 | 0.004880 | 默认参考 |
| `vless-xhttp-h2-tls-stream-up-download` | mixed | 普通 | mihomo | 2ce2b90 | 999.939 | 203.113 | 39.113 | 0.000000 | 默认参考 |
| `vless-xhttp-h2-tls-stream-up-download` | tcp | 普通 | mihomo | 2ce2b90 | 996.960 | 127.832 | 41.379 | N/A | 默认参考 |
| `vless-xhttp-h2-tls-stream-up-download` | udp | 普通 | mihomo | 2ce2b90 | 999.893 | 211.525 | 41.699 | 0.003760 | 默认参考 |
| `vless-xhttp-reality` | mixed | 普通 | mihomo | 3fdee46 | 999.925 | 210.514 | 36.797 | 0.000000 | 默认参考 |
| `vless-xhttp-reality` | tcp | 普通 | mihomo | 3fdee46 | 997.213 | 126.233 | 37.961 | N/A | 默认参考 |
| `vless-xhttp-reality` | udp | 普通 | mihomo | 3fdee46 | 999.783 | 217.758 | 39.152 | 0.003744 | 默认参考 |
| `vless-xray-http-cover` | mixed | 普通 | xray | 3fdee46 | 999.943 | 152.317 | 30.395 | 0.000000 | 默认参考 |
| `vless-xray-http-cover` | tcp | 普通 | xray | 3fdee46 | 999.870 | 39.763 | 29.957 | N/A | 默认参考 |
| `vless-xray-http-cover` | udp | 普通 | xray | 3fdee46 | 999.958 | 174.715 | 30.758 | 0.000000 | 默认参考 |
| `vless-xray-tcp-ech` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 159.708 | 32.348 | 0.000064 | 默认参考 |
| `vless-xray-tcp-ech` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 49.120 | 32.855 | N/A | 默认参考 |
| `vless-xray-tcp-ech` | udp | 普通 | mihomo | 2ce2b90 | 999.848 | 175.494 | 32.430 | 0.008464 | 默认参考 |
| `vless-xray-tcp-ech-chrome` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 173.118 | 32.742 | 0.000000 | 默认参考 |
| `vless-xray-tcp-ech-chrome` | tcp | 普通 | mihomo | 2ce2b90 | 999.660 | 45.335 | 32.812 | N/A | 默认参考 |
| `vless-xray-tcp-ech-chrome` | udp | 普通 | mihomo | 2ce2b90 | 999.902 | 182.426 | 32.191 | 0.003728 | 默认参考 |
| `vless-xray-xhttp-h3-auto` | mixed | 普通 | xray | e774a51 | 999.930 | 168.210 | 39.242 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-auto` | tcp | 普通 | xray | e774a51 | 997.930 | 117.085 | 40.527 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-auto` | udp | 普通 | xray | e774a51 | 997.899 | 193.858 | 39.262 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-auto-download` | mixed | 普通 | xray | e774a51 | 999.926 | 170.210 | 41.027 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-auto-download` | tcp | 普通 | xray | 2ce2b90 | 997.991 | 124.565 | 42.438 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-auto-download` | udp | 普通 | xray | e774a51 | 997.169 | 201.423 | 40.996 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-ech` | mixed | 普通 | xray | e774a51 | 999.920 | 170.746 | 38.977 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-ech` | tcp | 普通 | xray | e774a51 | 995.387 | 119.274 | 40.492 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-ech` | udp | 普通 | xray | e774a51 | 998.109 | 199.774 | 39.539 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-ech-download` | mixed | 普通 | xray | 3fdee46 | 999.945 | 217.544 | 39.281 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-ech-download` | tcp | 普通 | xray | 3fdee46 | 996.243 | 135.595 | 40.156 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-ech-download` | udp | 普通 | xray | 3fdee46 | 999.949 | 254.726 | 38.555 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-h2mux` | tcp | 普通 | xray | e774a51 | 999.441 | 123.351 | 35.469 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-packet-up` | mixed | 普通 | xray | e774a51 | 999.915 | 166.731 | 39.531 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-packet-up` | tcp | 普通 | xray | e774a51 | 995.990 | 115.118 | 40.379 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-packet-up` | udp | 普通 | xray | e774a51 | 998.822 | 197.395 | 39.387 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-packet-up-download` | mixed | 普通 | xray | e774a51 | 999.926 | 169.960 | 41.535 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-packet-up-download` | tcp | 普通 | xray | e774a51 | 998.437 | 124.064 | 42.371 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-packet-up-download` | udp | 普通 | xray | e774a51 | 998.062 | 196.445 | 41.309 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-packetaddr` | mixed | 普通 | xray | e774a51 | 999.868 | 177.424 | 39.398 | 0.010176 | 默认参考 |
| `vless-xray-xhttp-h3-packetaddr` | tcp | 普通 | xray | e774a51 | 998.218 | 116.719 | 40.523 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-packetaddr` | udp | 普通 | xray | e774a51 | 998.716 | 207.047 | 40.367 | 0.017440 | 默认参考 |
| `vless-xray-xhttp-h3-smux` | mixed | 普通 | xray | 6c3e3c2 | 821.103 | 172.940 | 35.949 | 35.317946 | Mihomo严格参考 |
| `vless-xray-xhttp-h3-smux` | tcp | 普通 | xray | 6c3e3c2 | 999.608 | 120.996 | 33.445 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-stream-one` | mixed | 普通 | xray | 3fdee46 | 999.941 | 207.946 | 37.090 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-stream-one` | tcp | 普通 | xray | 3fdee46 | 996.750 | 133.658 | 38.309 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-stream-one` | udp | 普通 | xray | 3fdee46 | 999.955 | 243.422 | 36.266 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-stream-up` | mixed | 普通 | xray | 3fdee46 | 999.938 | 213.180 | 37.078 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-stream-up` | tcp | 普通 | xray | 3fdee46 | 996.366 | 133.923 | 37.789 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-stream-up` | udp | 普通 | xray | 3fdee46 | 999.946 | 249.271 | 36.738 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-stream-up-download` | mixed | 普通 | xray | 3fdee46 | 999.933 | 224.255 | 38.133 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-stream-up-download` | tcp | 普通 | xray | 3fdee46 | 994.557 | 135.292 | 40.316 | N/A | 默认参考 |
| `vless-xray-xhttp-h3-stream-up-download` | udp | 普通 | xray | 3fdee46 | 999.959 | 251.294 | 38.652 | 0.000000 | 默认参考 |
| `vless-xray-xhttp-h3-yamux` | mixed | 普通 | xray | e774a51 | 932.503 | 167.718 | 36.531 | 13.458818 | Mihomo严格参考 |
| `vless-xray-xhttp-h3-yamux` | tcp | 普通 | xray | e774a51 | 999.669 | 110.969 | 36.289 | N/A | 默认参考 |
| `vmess` | mixed | 普通 | mihomo | 2ce2b90 | 999.944 | 172.682 | 28.562 | 0.000000 | 默认参考 |
| `vmess` | tcp | 普通 | mihomo | 2ce2b90 | 999.240 | 51.160 | 31.355 | N/A | 默认参考 |
| `vmess` | udp | 普通 | mihomo | 2ce2b90 | 999.693 | 183.525 | 24.840 | 0.000224 | 默认参考 |
| `vmess-grpc-plain` | mixed | 普通 | mihomo | 2ce2b90 | 999.938 | 200.319 | 30.207 | 0.000000 | 默认参考 |
| `vmess-grpc-plain` | tcp | 普通 | mihomo | 2ce2b90 | 998.437 | 131.200 | 33.660 | N/A | 默认参考 |
| `vmess-grpc-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.937 | 215.450 | 31.383 | 0.000000 | 默认参考 |
| `vmess-httpupgrade-plain-fast` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 166.525 | 29.363 | 0.000000 | 默认参考 |
| `vmess-httpupgrade-plain-fast` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 50.773 | 31.770 | N/A | 默认参考 |
| `vmess-httpupgrade-plain-fast` | udp | 普通 | mihomo | 2ce2b90 | 999.927 | 178.731 | 25.164 | 0.002784 | 默认参考 |
| `vmess-httpupgrade-plain-normal` | mixed | 普通 | mihomo | 2ce2b90 | 999.945 | 158.396 | 28.793 | 0.000000 | 默认参考 |
| `vmess-httpupgrade-plain-normal` | tcp | 普通 | mihomo | 2ce2b90 | 998.664 | 50.239 | 31.793 | N/A | 默认参考 |
| `vmess-httpupgrade-plain-normal` | udp | 普通 | mihomo | 2ce2b90 | 999.858 | 177.976 | 25.297 | 0.006384 | 默认参考 |
| `vmess-httpupgrade-tls-fast` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 173.578 | 30.566 | 0.000000 | 默认参考 |
| `vmess-httpupgrade-tls-fast` | tcp | 普通 | mihomo | 2ce2b90 | 999.485 | 54.144 | 33.621 | N/A | 默认参考 |
| `vmess-httpupgrade-tls-fast` | udp | 普通 | mihomo | 2ce2b90 | 999.943 | 191.214 | 26.641 | 0.000896 | 默认参考 |
| `vmess-httpupgrade-tls-normal` | mixed | 普通 | mihomo | 2ce2b90 | 999.941 | 178.682 | 30.836 | 0.000000 | 默认参考 |
| `vmess-httpupgrade-tls-normal` | tcp | 普通 | mihomo | 2ce2b90 | 999.022 | 53.191 | 33.762 | N/A | 默认参考 |
| `vmess-httpupgrade-tls-normal` | udp | 普通 | mihomo | 2ce2b90 | 999.929 | 196.224 | 26.680 | 0.000720 | 默认参考 |
| `vmess-tcp-chacha20-poly1305` | mixed | 普通 | mihomo | 2ce2b90 | 999.941 | 170.284 | 28.516 | 0.000000 | 默认参考 |
| `vmess-tcp-chacha20-poly1305` | tcp | 普通 | mihomo | 2ce2b90 | 999.538 | 54.366 | 31.266 | N/A | 默认参考 |
| `vmess-tcp-chacha20-poly1305` | udp | 普通 | mihomo | 2ce2b90 | 999.917 | 202.125 | 24.707 | 0.000000 | 默认参考 |
| `vmess-tcp-none` | mixed | 普通 | mihomo | 2ce2b90 | 999.942 | 153.492 | 27.312 | 0.000000 | 默认参考 |
| `vmess-tcp-none` | tcp | 普通 | mihomo | 2ce2b90 | 998.908 | 43.570 | 29.992 | N/A | 默认参考 |
| `vmess-tcp-none` | udp | 普通 | mihomo | 2ce2b90 | 999.945 | 181.606 | 24.934 | 0.000000 | 默认参考 |
| `vmess-tcp-packetaddr` | mixed | 普通 | mihomo | 2ce2b90 | 999.946 | 173.121 | 30.953 | 0.000000 | 默认参考 |
| `vmess-tcp-packetaddr` | tcp | 普通 | mihomo | 2ce2b90 | 999.905 | 49.629 | 31.320 | N/A | 默认参考 |
| `vmess-tcp-packetaddr` | udp | 普通 | mihomo | 2ce2b90 | 999.946 | 195.267 | 30.312 | 0.000480 | 默认参考 |
| `vmess-tcp-packetaddr-none` | mixed | 普通 | mihomo | 2ce2b90 | 999.940 | 164.069 | 30.059 | 0.000000 | 默认参考 |
| `vmess-tcp-packetaddr-none` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 43.886 | 29.812 | N/A | 默认参考 |
| `vmess-tcp-packetaddr-none` | udp | 普通 | mihomo | 2ce2b90 | 999.948 | 183.737 | 30.355 | 0.000112 | 默认参考 |
| `vmess-tcp-plain` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 170.953 | 28.672 | 0.000000 | 默认参考 |
| `vmess-tcp-plain` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 51.559 | 31.617 | N/A | 默认参考 |
| `vmess-tcp-plain` | udp | 普通 | mihomo | 2ce2b90 | 999.931 | 185.344 | 25.098 | 0.001840 | 默认参考 |
| `vmess-tcp-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.947 | 179.427 | 30.445 | 0.000000 | 默认参考 |
| `vmess-tcp-tls` | tcp | 普通 | mihomo | 2ce2b90 | 999.695 | 55.933 | 33.117 | N/A | 默认参考 |
| `vmess-tcp-tls` | udp | 普通 | mihomo | 2ce2b90 | 999.926 | 191.020 | 26.379 | 0.000144 | 默认参考 |
| `vmess-tcp-xudp` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 167.911 | 31.273 | 0.000000 | 默认参考 |
| `vmess-tcp-xudp` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 49.127 | 31.156 | N/A | 默认参考 |
| `vmess-v2ray-h2-plain` | mixed | 普通 | v2ray | 2ce2b90 | 999.946 | 210.160 | 33.398 | 0.000000 | 默认参考 |
| `vmess-v2ray-h2-plain` | tcp | 普通 | v2ray | 2ce2b90 | 994.566 | 132.298 | 36.430 | N/A | 默认参考 |
| `vmess-v2ray-h2-plain` | udp | 普通 | v2ray | 2ce2b90 | 999.580 | 243.562 | 31.824 | 0.000000 | 默认参考 |
| `vmess-v2ray-h2-tls` | mixed | 普通 | v2ray | 2ce2b90 | 999.944 | 227.082 | 34.398 | 0.000000 | 默认参考 |
| `vmess-v2ray-h2-tls` | tcp | 普通 | v2ray | 2ce2b90 | 997.528 | 149.636 | 37.797 | N/A | 默认参考 |
| `vmess-v2ray-h2-tls` | udp | 普通 | v2ray | 2ce2b90 | 999.907 | 263.996 | 33.516 | 0.000000 | 默认参考 |
| `vmess-v2ray-http-cover` | mixed | 普通 | v2ray | 2ce2b90 | 999.939 | 163.078 | 28.449 | 0.000000 | 默认参考 |
| `vmess-v2ray-http-cover` | tcp | 普通 | v2ray | 2ce2b90 | 997.720 | 55.851 | 30.789 | N/A | 默认参考 |
| `vmess-v2ray-http-cover` | udp | 普通 | v2ray | 2ce2b90 | 999.732 | 188.038 | 25.367 | 0.002048 | 默认参考 |
| `vmess-v2ray-ws-ed-header` | mixed | 普通 | v2ray | 2ce2b90 | 999.942 | 173.666 | 29.355 | 0.000000 | 默认参考 |
| `vmess-v2ray-ws-ed-header` | tcp | 普通 | v2ray | 2ce2b90 | 999.922 | 58.641 | 32.191 | N/A | 默认参考 |
| `vmess-v2ray-ws-ed-header` | udp | 普通 | v2ray | 2ce2b90 | 999.953 | 200.363 | 25.922 | 0.000000 | 默认参考 |
| `vmess-v2ray-ws-ed-path` | mixed | 普通 | v2ray | 2ce2b90 | 999.945 | 166.692 | 29.133 | 0.000000 | 默认参考 |
| `vmess-v2ray-ws-ed-path` | tcp | 普通 | v2ray | 2ce2b90 | 999.538 | 56.590 | 31.594 | N/A | 默认参考 |
| `vmess-v2ray-ws-ed-path` | udp | 普通 | v2ray | 2ce2b90 | 999.944 | 209.282 | 25.727 | 0.000000 | 默认参考 |
| `vmess-ws-plain` | mixed | 普通 | mihomo | 2ce2b90 | 999.943 | 168.231 | 30.148 | 0.000000 | 默认参考 |
| `vmess-ws-plain` | tcp | 普通 | mihomo | 2ce2b90 | 996.278 | 58.113 | 33.312 | N/A | 默认参考 |
| `vmess-ws-plain` | udp | 普通 | mihomo | 2ce2b90 | 999.885 | 188.496 | 25.879 | 0.000848 | 默认参考 |
| `vmess-ws-tls` | mixed | 普通 | mihomo | 2ce2b90 | 999.947 | 181.297 | 32.230 | 0.000000 | 默认参考 |
| `vmess-ws-tls` | tcp | 普通 | mihomo | 2ce2b90 | 999.922 | 56.271 | 35.457 | N/A | 默认参考 |
| `vmess-ws-tls` | udp | 普通 | mihomo | 2ce2b90 | 999.951 | 220.024 | 27.355 | 0.000000 | 默认参考 |

## HTTP处理主窗口（10项）

| 组合 | 流量 | 应用 | 对端 | Core代际 | 吞吐 Mbps | CPU % | RSS MiB | UDP丢包 % | 验收依据 |
|---|---|---|---|---|---:|---:|---:|---:|---|
| `body-h2` | mixed | 普通 | HTTP原站 | 6c3e3c2 | 999.921 | 176.297 | 42.453 | 0.000000 | 默认参考 |
| `disabled` | mixed | 普通 | HTTP原站 | 2ce2b90 | 997.898 | 103.389 | 29.867 | 0.000000 | 默认参考 |
| `disabled` | tcp | 普通 | HTTP原站 | 2ce2b90 | 999.989 | 45.781 | 29.422 | N/A | 默认参考 |
| `mitm-h1` | mixed | 普通 | HTTP原站 | 6c3e3c2 | 995.816 | 116.338 | 36.371 | 0.000000 | 默认参考 |
| `mitm-h1` | tcp | 普通 | HTTP原站 | 2ce2b90 | 1000.000 | 57.785 | 38.273 | N/A | 默认参考 |
| `mitm-h2` | mixed | 普通 | HTTP原站 | 6c3e3c2 | 997.892 | 140.272 | 37.223 | 0.000000 | 默认参考 |
| `mitm-h2` | tcp | 普通 | HTTP原站 | 6c3e3c2 | 998.346 | 83.325 | 42.801 | N/A | 默认参考 |
| `plain-rewrite` | mixed | 普通 | HTTP原站 | 6c3e3c2 | 997.895 | 112.867 | 32.438 | 0.000000 | 默认参考 |
| `plain-rewrite` | tcp | 普通 | HTTP原站 | 2ce2b90 | 998.754 | 48.749 | 33.930 | N/A | 默认参考 |
| `unmatched` | mixed | 普通 | HTTP原站 | 2ce2b90 | 999.984 | 115.768 | 31.141 | 0.000000 | 默认参考 |

## 额外保护与控制（5项）

| 组合 | 流量 | 应用 | 对端 | Core代际 | 吞吐 Mbps | CPU % | RSS MiB | UDP丢包 % | 验收依据 |
|---|---|---|---|---|---:|---:|---:|---:|---|
| `vless-tcp-tls-smux` | tcp | 普通 | mihomo | 6c3e3c2 | 936.038 | 61.966 | 38.430 | N/A | 相对10% |
| `vless-xray-xhttp-h3-h2mux` | mixed | 普通 | xray | 2ce2b90 | 951.559 | 193.906 | 36.602 | 9.486360 | Mihomo严格参考 |
| `vless-xray-xhttp-h3-h2mux` | udp | 普通 | xray | e774a51 | 595.449 | 179.135 | 39.605 | 40.204311 | Mihomo严格参考 |
| `vless-xray-xhttp-h3-smux` | udp | 普通 | xray | 6c3e3c2 | 689.758 | 187.451 | 38.883 | 30.751279 | 相对10% |
| `vless-xray-xhttp-h3-yamux` | udp | 普通 | xray | 2ce2b90 | 754.421 | 171.872 | 38.977 | 24.321550 | Mihomo严格参考 |

## 匹配Mihomo的最终参考指标

仅列按参考验收的18项，各用自身配对。Mihomo错误内容仍计实际吞吐，完整性独立列示；其RSS不豁免Vole内存。

| 组合 | 流量 | 应用 | Vole Mbps | Vole CPU % | Vole RSS MiB | Vole丢包 % | Mihomo Mbps | Mihomo CPU % | Mihomo RSS MiB | Mihomo丢包 % | Mihomo完整性 |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `hysteria2-native-brutal-salamander` | mixed | 普通 | 983.349 | 206.803 | 37.980 | 1.726564 | 989.339 | 242.873 | 211.926 | 2.120485 | PASS |
| `hysteria2-native-hop` | udp | 普通 | 981.579 | 206.016 | 34.383 | 1.837413 | 957.261 | 225.898 | 130.504 | 4.267579 | PASS |
| `hysteria2-native-hop-salamander` | udp | 普通 | 988.349 | 213.756 | 35.359 | 1.159539 | 922.327 | 234.680 | 124.809 | 7.712484 | PASS |
| `hysteria2-native-mtls` | udp | 普通 | 984.614 | 211.907 | 35.234 | 1.162819 | 888.743 | 270.767 | 346.309 | 11.063596 | PASS |
| `ss-rust-eih-aes128` | mixed | 普通 | 990.202 | 150.054 | 31.516 | 1.811557 | 987.976 | 165.196 | 95.812 | 2.392390 | PASS |
| `ss-rust-eih-aes128` | udp | 普通 | 916.464 | 184.021 | 30.906 | 8.350661 | 689.989 | 171.303 | 90.113 | 30.911167 | PASS |
| `ss-rust-eih-aes256` | mixed | 普通 | 991.770 | 154.615 | 31.473 | 1.633828 | 977.177 | 168.317 | 95.988 | 4.550700 | PASS |
| `ss-rust-eih-aes256` | udp | 普通 | 932.762 | 183.125 | 30.898 | 6.717953 | 701.502 | 176.949 | 91.863 | 29.821532 | PASS |
| `vless-tcp-tls-h2mux` | udp | 普通 | 599.105 | 185.394 | 36.215 | 39.840150 | 494.198 | 217.820 | 126.266 | 50.301249 | PASS |
| `vless-tcp-tls-h2mux-brutal` | udp | 普通 | 629.436 | 187.925 | 36.102 | 36.811758 | 484.571 | 215.522 | 124.730 | 51.262323 | PASS |
| `vless-tcp-tls-smux` | tcp | 普通 | 936.038 | 61.966 | 38.430 | N/A | 999.922 | 41.140 | 104.309 | N/A | PASS |
| `vless-v2ray-ws-ed-header` | udp | 普通 | 999.943 | 190.767 | 25.699 | 0.000000 | 999.954 | 220.704 | 90.461 | 0.000000 | PASS |
| `vless-xray-xhttp-h3-h2mux` | mixed | 普通 | 951.559 | 193.906 | 36.602 | 9.486360 | 706.471 | 165.838 | 167.113 | 10.763964 | FAIL |
| `vless-xray-xhttp-h3-h2mux` | udp | 普通 | 595.449 | 179.135 | 39.605 | 40.204311 | 543.529 | 181.767 | 134.961 | 45.367460 | PASS |
| `vless-xray-xhttp-h3-smux` | mixed | 普通 | 821.103 | 172.940 | 35.949 | 35.317946 | 729.151 | 136.345 | 151.367 | 49.351902 | PASS |
| `vless-xray-xhttp-h3-smux` | udp | 普通 | 689.758 | 187.451 | 38.883 | 30.751279 | 712.289 | 204.069 | 127.840 | 28.687353 | PASS |
| `vless-xray-xhttp-h3-yamux` | mixed | 普通 | 932.503 | 167.718 | 36.531 | 13.458818 | 725.088 | 107.853 | 162.312 | 49.474367 | PASS |
| `vless-xray-xhttp-h3-yamux` | udp | 普通 | 754.421 | 171.872 | 38.977 | 24.321550 | 683.208 | 169.793 | 131.672 | 31.607537 | PASS |

原始运行目录、日志、采样、候选补丁及过程报告已清理。两个运行账本保持原样，其旧canonical字段仅为历史标识与指纹，不表示文件仍在；未将其改指新的总结或补造缺失数据。
