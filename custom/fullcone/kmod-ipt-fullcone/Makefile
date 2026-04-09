# SPDX-License-Identifier: GPL-2.0-only
#
# OpenWrt package: kmod-ipt-fullcone + iptables-mod-fullcone
#
# Builds the iptables-only flavour of the unified fullcone NAT engine. This
# package has NO build-time or run-time dependency on any nftables module.

include $(TOPDIR)/rules.mk

PKG_NAME:=fullcone-ipt
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_PARALLEL:=1

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=turboacc

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/ipt-fullcone
  SUBMENU:=Netfilter Extensions
  TITLE:=Unified fullcone NAT (iptables target)
  DEPENDS:=+kmod-ipt-core +kmod-nf-nat +kmod-nf-conntrack
  KCONFIG:= \
	CONFIG_NF_CONNTRACK_EVENTS=y
  FILES:=$(PKG_BUILD_DIR)/xt_FULLCONE.ko
  AUTOLOAD:=$(call AutoProbe,xt_FULLCONE)
endef

define KernelPackage/ipt-fullcone/description
 Endpoint-Independent Mapping (RFC 4787 "full cone") NAT for iptables.

 Uses the kernel conntrack expectation system for the inbound DNAT path
 (Broadcom-style high-performance design) plus a per-netns auxiliary index
 for O(1) outbound (internal -> external) lookup. UDP+TCP+ICMP and IPv4+IPv6
 are all supported.

 This is the iptables flavour. It does not depend on, conflict with, or
 share any code with the nftables fullcone package.
endef

define Package/iptables-mod-fullcone
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=Unified fullcone NAT (iptables userspace)
  DEPENDS:=+iptables +libxtables +kmod-ipt-fullcone
endef

define Package/iptables-mod-fullcone/description
 Userspace iptables/ip6tables extension for the FULLCONE target.
 Use as: iptables -t nat -A POSTROUTING -o $$wan -j FULLCONE
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	# Kernel module
	+$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
	# Userspace iptables extension (.so loaded by iptables/ip6tables)
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -I$(PKG_BUILD_DIR) \
		-fPIC -shared -o $(PKG_BUILD_DIR)/libxt_FULLCONE.so \
		$(PKG_BUILD_DIR)/libxt_FULLCONE.c
endef

define Package/iptables-mod-fullcone/install
	$(INSTALL_DIR) $(1)/usr/lib/iptables
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libxt_FULLCONE.so $(1)/usr/lib/iptables/
endef

$(eval $(call KernelPackage,ipt-fullcone))
$(eval $(call BuildPackage,iptables-mod-fullcone))
