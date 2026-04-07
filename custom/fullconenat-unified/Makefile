# SPDX-License-Identifier: GPL-2.0-only
#
# Unified Full Cone NAT module
# Supports iptables (FULLCONENAT target) and nftables (fullcone expression)

include $(TOPDIR)/rules.mk

PKG_NAME:=fullconenat
PKG_VERSION:=2.0.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/fullcone-nat
  SUBMENU:=Netfilter Extensions
  TITLE:=Unified Full Cone NAT module
  DEPENDS:=+kmod-nf-nat +kmod-nf-conntrack
  KCONFIG:= \
    CONFIG_NF_CONNTRACK_EVENTS=y \
    CONFIG_NF_CONNTRACK_CHAIN_EVENTS=y
  FILES:=$(PKG_BUILD_DIR)/fullcone_nat.ko
  AUTOLOAD:=$(call AutoProbe,fullcone_nat)
endef

define KernelPackage/fullcone-nat/description
  Unified Full Cone NAT kernel module. Uses conntrack expectations
  for port mapping storage (per-net namespace isolation). Supports
  IPv4/IPv6, UDP/TCP, iptables and nftables simultaneously.
endef

# Virtual package for nftables dependency resolution.
# The fullcone nft expression is included in kmod-fullcone-nat.
define KernelPackage/nft-fullcone
  SUBMENU:=Netfilter Extensions
  DEPENDS:=+kmod-fullcone-nat +kmod-nft-nat
  TITLE:=nftables fullcone expression (virtual)
endef

define KernelPackage/nft-fullcone/description
  Virtual package. The fullcone nftables expression is provided by
  kmod-fullcone-nat. This package exists for dependency resolution.
endef

# iptables userspace extension: FULLCONENAT target
define Package/iptables-mod-fullconenat
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FULLCONENAT iptables extension
  DEPENDS:=+libxtables +kmod-fullcone-nat
endef

define Build/Compile
	+$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
	$(call Build/Compile/Default)
endef

define Package/iptables-mod-fullconenat/install
	$(INSTALL_DIR) $(1)/usr/lib/iptables
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libipt_FULLCONENAT.so $(1)/usr/lib/iptables
endef

$(eval $(call KernelPackage,fullcone-nat))
$(eval $(call KernelPackage,nft-fullcone))
$(eval $(call BuildPackage,iptables-mod-fullconenat))
