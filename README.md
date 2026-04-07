# luci-app-turboacc

一个适用于官方Official OpenWrt(24.10/25.12/snapshot) firewall3/firewall4的turboacc
包括以下功能：快速转发引擎、全锥形 NAT1、TCP 拥塞控制算法
支持内核版本：6.6、6.12、6.18

目前仅测试了2025-11-20的x86平台的snapshot版本OpenWrt，fw3(iptables)和fw4(nftables)均可用

## 使用方法

+ 在openwrt源代码所在目录执行：

    ```bash
    curl -sSL https://raw.githubusercontent.com/mufeng05/turboacc/unified-fullcone/add_turboacc.sh -o add_turboacc.sh && bash add_turboacc.sh
    ```

    脚本会自动从 `unified-fullcone` 分支拉取代码，并根据当前源码树的内核版本匹配对应的补丁。

    如果需要指定其他分支，可以设置环境变量：

    ```bash
    TURBOACC_BRANCH=main bash add_turboacc.sh
    ```

+ 之后执行

```bash
make menuconfig
```

+ 在 > LuCI > 3. Applications中选中luci-app-turboacc
+ Full Cone NAT 默认启用（`Include fullcone NAT` 选项），无需额外配置。该选项会自动拉取统一 fullcone 模块，fw3/fw4 环境均适用。

## Full Cone NAT

本项目使用统一的 fullcone NAT 内核模块 `fullcone_nat.ko`（位于 `custom/fullconenat-unified/`），取代了之前的三种独立实现（CHION xt_FULLCONENAT、Broadcom fullcone、nft_fullcone）。

### 特性

- **单一模块同时支持 iptables 和 nftables**：在 fw3 下注册为 `FULLCONENAT` target，在 fw4 下注册为 `fullcone` nft expression
- **基于 conntrack expectation**：不使用自建哈希表，所有端口映射存储在内核 conntrack expectation 表中，天然支持网络命名空间隔离
- **IPv4 + IPv6**：同时支持双栈 fullcone NAT
- **UDP + TCP**：UDP 立即创建映射，TCP 在连接建立后创建映射
- **RFC 4787 端口奇偶校验**：偶数端口映射到偶数，奇数端口映射到奇数
- **无内核侵入**：独立 .ko 模块，不修改 `nf_nat_masquerade.c` 等内核核心文件，升级内核无需重新适配补丁

### 与旧方案的对比

| | CHION xt_FULLCONENAT | Broadcom Fullcone | 统一模块 fullcone_nat |
|---|---|---|---|
| 形态 | 独立 .ko | 内核补丁 | 独立 .ko |
| iptables | 支持 | 支持 | 支持 |
| nftables | 不支持 | 部分支持 | 支持 |
| IPv6 | 支持 | 不支持 | 支持 |
| TCP | 支持 | 不支持 | 支持 |
| 映射存储 | 自建哈希表 | conntrack expectation | conntrack expectation |
| 命名空间隔离 | 无 | 有 | 有 |
| 内核侵入 | 无 | 高（修改核心文件） | 无 |

## 目录结构

```
lede/                          # 上游 LEDE 仓库的文件镜像（仅供对比，不做修改）
├── luci-app-turboacc/         # LuCI 界面
├── shortcut-fe/               # SFE 加速引擎
├── hack-6.*/                  # 内核补丁（conntrack events、SFE 等）
├── pending-6.*/               # 可选内核补丁
└── patches/                   # firewall/nftables/libnftnl 用户态补丁

custom/                        # 自定义覆盖文件（覆盖 lede/ 中的同名文件）
├── fullconenat-unified/       # 统一 fullcone NAT 内核模块源码
│   ├── Makefile               # OpenWrt 包定义
│   └── src/
│       ├── fullcone.h         # 共享头文件
│       ├── fullcone_core.c    # 核心逻辑（helper、expectation、端口分配）
│       ├── fullcone_xt.c      # iptables 集成 + 模块入口
│       ├── fullcone_nft.c     # nftables 集成
│       └── libipt_FULLCONENAT.c  # iptables 用户态扩展
├── luci-app-turboacc/         # LuCI 覆盖文件
│   ├── Makefile               # 包依赖定义
│   ├── htdocs/.../turboacc.js # 前端界面（移除旧选项）
│   └── root/
│       ├── etc/uci-defaults/  # 初始配置
│       └── usr/share/rpcd/    # RPC 检测（fullcone_nat.ko）
├── hack-6.*/                  # 版本特定的自定义内核补丁
├── patches/                   # 自定义用户态补丁覆盖
└── shortcut-fe/               # SFE 自定义补丁
```

## 注意

1. **优先使用 `Flow Offloading`**：`Flow Offloading` 是 Linux 内核原生的流量卸载方案（4.16+ 引入），兼容 nftables，支持进一步卸载到硬件，是长期推荐的加速方案。
2. **`firewall4`(nftables) 环境下请使用 `Flow Offloading`**：`Shortcut-FE` 和 `Fast Classifier` 依赖 iptables 时代的 conntrack chain events 接口，与 nftables 不兼容。OpenWrt 23.05+ 默认使用 `firewall4`/nftables，在此环境下选择 SFE 类方案会存在兼容性风险。
3. **仅在 `firewall3`(iptables) 环境下可选 `Fast Classifier` 或 `Shortcut-FE`**：如果你的固件使用的是 `firewall3`/iptables，可以根据需要选择 `Fast Classifier` 或 `Shortcut-FE CM` 作为加速引擎。
4. 因OpenWrt现在使用`firewall4`作为默认防火墙，如果切换为`firewall3`的话，请把所有与nft相关的包手动取消掉，并替换为相应的ipt包(例如: `iptables-nft`替换为`iptables-zz-legacy`)。

## 插件预览

![fw3预览](https://raw.githubusercontent.com/mufeng05/turboacc/main/img/fw3.png)
![fw4预览](https://raw.githubusercontent.com/mufeng05/turboacc/main/img/fw4.png)

## 关于

此仓库的luci-app-turboacc是基于lede的[luci-app-turboacc](https://github.com/coolsnowwolf/luci/tree/openwrt-23.05/applications/luci-app-turboacc)和chenmozhijin的[turboacc](https://github.com/chenmozhijin/turboacc)修改而来的，保留了lede版luci-app-turboacc的所有功能。

## 感谢

 感谢以下项目：

+ [openwrt/openwrt](https://github.com/openwrt/openwrt)
+ [coolsnowwolf/lede](https://github.com/coolsnowwolf/lede)
+ [coolsnowwolf/luci](https://github.com/coolsnowwolf/luci)
+ [chenmozhijin/turboacc](https://github.com/chenmozhijin/turboacc)
