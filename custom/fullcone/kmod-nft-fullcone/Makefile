# SPDX-License-Identifier: GPL-2.0-only
#
# OpenWrt package: kmod-nft-fullcone-unified
#
# Builds the nftables-only flavour of the unified fullcone NAT engine. This
# package has NO build-time or run-time dependency on any iptables (xtables)
# module.
#
# Named "-unified" to coexist alongside the legacy kmod-nft-fullcone package
# from the upstream nft-fullcone project, which is also shipped under
# package/turboacc/fullconenat-nft. The two MUST NOT be enabled together.

include $(TOPDIR)/rules.mk

PKG_NAME:=fullcone-nft-unified
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_PARALLEL:=1

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=turboacc

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/nft-fullcone-unified
  SUBMENU:=Netfilter Extensions
  TITLE:=Unified fullcone NAT (nftables expression)
  DEPENDS:=+kmod-nft-nat +kmod-nf-conntrack
  CONFLICTS:=kmod-nft-fullcone
  KCONFIG:= \
	CONFIG_NF_CONNTRACK_EVENTS=y \
	CONFIG_NF_TABLES=y
  FILES:=$(PKG_BUILD_DIR)/nft_FULLCONE.ko
  AUTOLOAD:=$(call AutoProbe,nft_FULLCONE)
endef

define KernelPackage/nft-fullcone-unified/description
 Endpoint-Independent Mapping (RFC 4787 "full cone") NAT for nftables.

 Uses the kernel conntrack expectation system for the inbound DNAT path
 (Broadcom-style high-performance design) plus a per-netns auxiliary index
 for O(1) outbound (internal -> external) lookup. UDP+TCP+ICMP and IPv4+IPv6
 are all supported.

 This is the nftables flavour. It does not depend on, conflict with, or
 share any code with the iptables fullcone package.

 Use as:
   table inet nat {
       chain postrouting {
           type nat hook postrouting priority srcnat;
           oifname "wan" fullcone
       }
   }
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	+$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
endef

$(eval $(call KernelPackage,nft-fullcone-unified))
