# 统一全锥形 NAT (Unified fullcone NAT)

按 RFC 4787 Endpoint-Independent Mapping（俗称 "full cone"）重写的 Linux
netfilter NAT 实现，发布形式是**两个完全独立的内核模块**：

| 模块               | 前端     | 包目录                  |
|--------------------|----------|-------------------------|
| `xt_FULLCONE.ko`   | iptables | `kmod-ipt-fullcone/`    |
| `nft_FULLCONE.ko`  | nftables | `kmod-nft-fullcone/`    |

两个 `.ko` **在二进制层面零共享**：互相不依赖，也不会引用对方所属防火墙
框架（iptables / nftables）的任何符号。它们都从同一份引擎源码
`fc_engine.c` 编译而来——通过 `#include` 直接嵌入到各自的编译单元，使所有
引擎符号变成 file-static，不会出现在 `.ko` 的导出符号表里。

## 为什么要重写

本实现是已有三种方案的优点的并集，缺点的交集：

| 维度                              | xt_FULLCONENAT | nft_fullcone | BCM 内核 patch | 本实现 |
|-----------------------------------|----------------|--------------|----------------|--------|
| 入站 DNAT                         | 自建哈希       | 自建哈希     | conntrack expectation | conntrack expectation |
| 出站 (int → ext) 反查             | 自建哈希       | 自建哈希     | 全表扫描 O(N)         | per-netns 辅助哈希 O(1) |
| per-netns 状态                    | 否（全局）     | 否（全局）   | 否（全局）            | 是 |
| IPv6                              | 是             | 是           | 否                    | 是 |
| TCP fullcone                      | 否             | 否           | 否                    | 是 |
| 以可加载模块方式实现              | 是             | 是           | 否（需打 patch）      | 是 |
| 入站需要规则                      | 是 (PREROUTING)| 是           | 否                    | 否 |

关键洞察来自 in-tree Broadcom 风格的 patch：内核的 conntrack
**expectation** 子系统天然就是入站 DNAT 通路所需要的查找机制。把 fullcone
映射存成 expectation，就同时获得：

* O(1) 入站查找（折叠进 conntrack 本来就要做的查找里）
* 入站热路径上没有任何自定义 spinlock
* 不需要显式的 PREROUTING 规则
* 自动 per-netns 隔离
* 自动 GC，跟随 conntrack expectation 生命周期

Broadcom 的 patch 只优化了入站；它的出站端口复用是线性遍历整张
expectation 哈希。本实现在它的基础上加了一个**以内部端点为键**的小型
per-netns 辅助索引，使出站 (int → ext) 反查也变成 O(1)。

## 架构

```
                              ┌──────────────────────────┐
                              │   per-netns 辅助哈希     │
                              │ (int_addr,int_port,proto)│
                              │   → fc_binding → exp     │
                              └────────────┬─────────────┘
                                           │
  出站包                                   │  入站包
       │                                   │       │
       v                                   │       v
  ┌──────────┐   1) 反查 binding           │  ┌──────────────┐
  │ POSTROUT │  ───────────────────────────┘  │  conntrack   │
  │ FULLCONE │                                │  expect 查找  │
  │  target  │   2) 复用 OR 分配新           │              │
  └────┬─────┘      (ext_addr, port)          └──────┬───────┘
       │                                             │
       v                                             v
  nf_nat_setup_info()                          fc_expectfn()
  nf_ct_expect_related()                       nf_nat_setup_info(DNAT)
       │                                             │
       v                                             v
  以 src=(ext_addr, ext_port)                  以 dst=(int_addr, int_port)
  发出去                                       投递回内部端点
```

辅助哈希**每条出站流只查一次**（即每个新建 conntrack 一次），不是每个包
一次。同一条流后续包走的是标准内核 NAT mangling 流程，引擎零开销。

## 源码布局

```
custom/fullcone/
├── core/                          引擎源码（唯一一份）
│   ├── fc_engine.c
│   └── fc_engine.h
├── kmod-ipt-fullcone/             OpenWrt 包（iptables 版）
│   ├── Makefile
│   └── src/
│       ├── Kbuild
│       ├── xt_FULLCONE.{c,h}
│       └── libxt_FULLCONE.c
└── kmod-nft-fullcone/             OpenWrt 包（nftables 版）
    ├── Makefile
    └── src/
        ├── Kbuild
        └── nft_fullcone.c
```

引擎只在 `core/fc_engine.{c,h}` 这一个地方存在。两个包的 `src/` **不**自带
拷贝，而是由 `add_turboacc.sh` 在安装阶段把引擎文件分发到各自的 `src/`
里——这样 OpenWrt 构建树里能拿到两个完整自包含的包，而源码树本身保持单一
真源（DRY）。

如果想绕开脚本直接在本地迭代编译，先手动把引擎拷过去：

```sh
cp custom/fullcone/core/fc_engine.* custom/fullcone/kmod-ipt-fullcone/src/
cp custom/fullcone/core/fc_engine.* custom/fullcone/kmod-nft-fullcone/src/
```

`src/fc_engine.*` 已被 `.gitignore` 故意忽略，**不要**提交到任何包目录
里——那正是我们想避免的重复。

## 编译

执行顶层的 `add_turboacc.sh` 之后，两个包会出现在 OpenWrt 源码树的
`package/turboacc/kmod-ipt-fullcone/` 和 `package/turboacc/kmod-nft-fullcone/`
下，分别用以下命令编译：

```sh
make package/turboacc/kmod-ipt-fullcone/compile      # iptables 版
make package/turboacc/kmod-nft-fullcone/compile      # nftables 版
```

OpenWrt 包名（在 `menuconfig` 的 `Kernel modules → Netfilter Extensions`
里勾选）：

* `kmod-ipt-fullcone` + `iptables-mod-fullcone` —— iptables target `FULLCONE`
* `kmod-nft-fullcone-unified` —— nftables expression `fullcone`

nftables 包声明了 `CONFLICTS:=kmod-nft-fullcone`，所以无法和旧的
nft-fullcone 包同时被勾选（两者注册的 expression 同名 `fullcone`，会冲突）。
两个包的 Build/Prepare 流程互不共享。

## 用法

### iptables

```sh
iptables  -t nat -A POSTROUTING -o $WAN -j FULLCONE
ip6tables -t nat -A POSTROUTING -o $WAN -j FULLCONE
```

**不需要** PREROUTING 规则。入站 DNAT 由引擎注册到 conntrack 的 expectation
系统自动处理。

可选参数（与 MASQUERADE 同名）：

```
--to-source <ipaddr>[-<ipaddr>]   指定外部源 IP（或地址池）
--to-ports  <port>[-<port>]       限定外部端口范围
--random                          随机化源端口
--random-fully                    完全随机化源端口
--persistent                      规则重载时保持同一映射
```

### nftables

```nft
table inet nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "wan" fullcone
    }
}
```

和 iptables 一样：不需要 prerouting 规则。

## 支持范围

* IPv4 + IPv6（两个前端都支持）
* UDP 和 TCP
* Endpoint-Independent Mapping（RFC 4787 REQ-1）
* Endpoint-Independent Filtering —— 由 conntrack expectation 系统天然提供
* UDP 端口保留（RFC 4787 REQ-4）和奇偶保持（RFC 4787 REQ-3）
* 按 network namespace 隔离（容器宿主友好，符合 RFC 6146 思路）
* 地址池 (`--to-source 1.2.3.4-1.2.3.10`)
* 端口范围 (`--to-ports 10000-20000`)

## **不**支持的部分

* ICMP。ICMP 的 identifier 字段位于 conntrack tuple 的 *src* 一侧，而我们
  的设计假设标识符在 *dst* 一侧，要支持 ICMP 需要一条平行的代码路径。
  欢迎 PR。
* SCTP / GRE / DCCP / UDPLite。前两者在家用路由器上很少 NAT；引擎对这些
  协议的 ct 直接放行不动。
* Hairpin NAT —— 由内核标准的 `MASQUERADE` 基础设施处理（前提是链上配置
  了相应规则）。

## 兼容性

目标内核 Linux 5.15 → 6.18。已在 OpenWrt main 分支上的内核 6.6、6.12、
6.18 三个版本里通过基本验证。

## 许可证

GPL-2.0-only.
