# luci-app-turboacc

一个适用于官方Official OpenWrt(24.10/25.12/snapshot) firewall3/firewall4的turboacc
包括以下功能：快速转发引擎、全锥形 NAT1（含全新统一实现）、TCP 拥塞控制算法
支持内核版本：6.6、6.12、6.18

目前仅测试了2025-11-20的x86平台的snapshot版本OpenWrt，fw3(iptables)和fw4(nftables)均可用

## 使用方法

+ 在openwrt源代码所在目录执行：

    ```bash
    curl -sSL https://raw.githubusercontent.com/mufeng05/turboacc/main/add_turboacc.sh -o add_turboacc.sh && bash add_turboacc.sh
    ```

    脚本会自动读取当前源码树的内核版本，并匹配对应的补丁。

+ 之后执行

```bash
make menuconfig
```

+ 在 > LuCI > 3. Applications中选中luci-app-turboacc

## 注意

1. **优先使用 `Flow Offloading`**：`Flow Offloading` 是 Linux 内核原生的流量卸载方案（4.16+ 引入），兼容 nftables，支持进一步卸载到硬件，是长期推荐的加速方案。
2. **`firewall4`(nftables) 环境下请使用 `Flow Offloading`**：`Shortcut-FE` 和 `Fast Classifier` 依赖 iptables 时代的 conntrack chain events 接口，与 nftables 不兼容。OpenWrt 23.05+ 默认使用 `firewall4`/nftables，在此环境下选择 SFE 类方案会存在兼容性风险。
3. **仅在 `firewall3`(iptables) 环境下可选 `Fast Classifier` 或 `Shortcut-FE`**：如果你的固件使用的是 `firewall3`/iptables，可以根据需要选择 `Fast Classifier` 或 `Shortcut-FE CM` 作为加速引擎。
4. 因OpenWrt现在使用`firewall4`作为默认防火墙，如果切换为`firewall3`的话，请把所有与nft相关的包手动取消掉，并替换为相应的ipt包(例如: `iptables-nft`替换为`iptables-zz-legacy`)。

## 关于全锥形 NAT 的两套实现

本仓库现在同时提供 **两套** 全锥形（fullcone）NAT 实现，可按需选择：

### A. 旧实现（默认开启，兼容上游）

- iptables 侧：`kmod-ipt-fullconenat` + `iptables-mod-fullconenat`
- nftables 侧：`kmod-nft-fullcone`（来自 nft-fullcone 项目）
- 同时叠加内核 patch `982-add-bcm-fullconenat-support` / `983-add-bcm-fullconenat-to-nft`，让 `MASQUERADE` 自身具备 fullcone 能力
- 仅 UDP；入站需要 PREROUTING 规则（旧 nft/ipt 模块）

### B. 新统一实现（位于 `custom/fullcone/`）

- iptables 侧：`kmod-ipt-fullcone` + `iptables-mod-fullcone`（target 名 `FULLCONE`）
- nftables 侧：`kmod-nft-fullcone-unified`（expression 名 `fullcone`）
- 两个内核模块**完全独立编译**，依赖严格隔离：iptables 模块不依赖任何 nftables 模块，反之亦然
- 共用同一份核心引擎源码（`fc_engine.c`），通过 `#include` 静态嵌入到各自的 `.ko`，所有引擎符号 `static`，不会产生符号冲突
- 设计要点：
  - **入站 DNAT 走 conntrack expectation**（继承 Broadcom 思路），无自建哈希、无自定义自旋锁
  - **出站 (int → ext) 反查使用 per-netns 辅助索引**，O(1) 查找，避免 BCM 全表扫描
  - **所有状态 per-netns**，修复了三种已有实现的全局状态问题
  - **支持 UDP + TCP × IPv4 + IPv6**
  - **不修改任何内核源码**，纯模块方式
  - **不需要 PREROUTING 规则**，入站 DNAT 由 conntrack expectation 自动完成
- 用法：
  - iptables: `iptables -t nat -A POSTROUTING -o $WAN -j FULLCONE`
  - nftables: `oifname "wan" fullcone`（放在 `type nat hook postrouting` 链中即可）
- 详细文档见 [`custom/fullcone/README.md`](./custom/fullcone/README.md)

> 二者**不要同时启用**：旧实现叠加了 BCM 内核 patch 让 `MASQUERADE` 自动 fullcone，而新实现是显式 target/expression。同链路上同时存在两套 NAT 流程会互相干扰。**建议默认继续使用 A 方案**，需要更高性能 / 更完整协议覆盖（如 TCP fullcone）时可在 menuconfig 中切换到 B 方案。

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
