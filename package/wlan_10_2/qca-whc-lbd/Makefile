include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-whc-lbd
PKG_SOURCE_PROTO:=git
PKG_BRANCH:=whc/banana
PKG_RELEASE:=1

include $(INCLUDE_DIR)/local-development.mk
ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_VERSION:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
endif
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)

WIFI_10_4_A:=PACKAGE_kmod-qca-wifi-10.4-akronite-perf
WIFI_10_4_D:=PACKAGE_kmod-qca-wifi-10.4-dakota-perf
WIFI_10_4_MIPS:=PACKAGE_kmod-qca-wifi-10.4-perf
WIFI_10_2_MIPS:=PACKAGE_kmod-qca-wifi-perf
WIFI_10_2_ARM:=PACKAGE_kmod-qca-wifi-akronite-perf
WIFI_10_4_MIPS_UNIFIED:=PACKAGE_kmod-qca-wifi-10.4-unified-perf
WIFI_PKGS:=$(WIFI_10_4_A)||$(WIFI_10_4_D)||$(WIFI_10_4_MIPS)||$(WIFI_10_2_MIPS)||$(WIFI_10_2_ARM)||$(WIFI_10_4_MIPS_UNIFIED)

PKG_BUILD_DEPENDS:=$(WIFI_10_4_A):qca-wifi-10.4 $(WIFI_10_4_D):qca-wifi-10.4 \
	$(WIFI_10_2_MIPS):qca-wifi $(WIFI_10_2_ARM):qca-wifi $(WIFI_10_4_MIPS):qca-wifi-10.4 \
	$(WIFI_10_4_MIPS_UNIFIED):qca-wifi-10.4 libhyficommon

QCAWHCLBD_MAKE_OPTS:= \
        CROSS=$(TARGET_CROSS) \
        GWLIB=$(STAGING_DIR)/usr/lib \
        LBTOP=$(PKG_BUILD_DIR) \
        GWINCLUDE=$(STAGING_DIR)/usr/include/hyficommon \
        ATHDIR=$(STAGING_DIR)/usr/include \
        INSTALL_ROOT=$(PKG_BUILD_DIR)/install \
        STAGING_DIR=$(STAGING_DIR)

ifeq ($(CONFIG_LBD_SUPPORT_VHT160),y)
QCAWHCLBD_MAKE_OPTS+=LBD_SUPPORT_VHT160=y
endif

include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

define Package/qca-whc-lbd/config
  source "$(SOURCE)/Config.in"
  $(call Package/$(PKG_NAME)/override_version,$(PKG_NAME))
  $(call Package/$(PKG_NAME)/override_source_path,$(PKG_NAME))
endef

define Package/qca-whc-lbd
  SECTION:=QCA
  CATEGORY:=QCA Proprietary software
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
  DEPENDS:=+qca-whc-init +libhyficommon +libpthread +@BUSYBOX_CONFIG_STAT \
	   +@BUSYBOX_CONFIG_FEATURE_STAT_FORMAT \
	   @$(WIFI_PKGS)
  TITLE:=Whole Home Coverage Load Balancing daemon
  SUBMENU:=Whole Home Coverage features
endef

define Package/qca-whc-lbd/description
  This package installs the Whole Home Coverage Load Balancing daemon
endef

define Build/Compile
	mkdir -p $(PKG_BUILD_DIR)/install/lib
	mkdir -p $(PKG_BUILD_DIR)/install/include
	mkdir -p $(PKG_BUILD_DIR)/install/sbin
	$(MAKE) -C $(PKG_BUILD_DIR) $(strip $(QCAWHCLBD_MAKE_OPTS)) subdirs
endef

define Package/qca-whc-lbd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/lib/functions/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/install/sbin/lbd $(1)/usr/sbin
	$(INSTALL_BIN) ./files/lbt $(1)/usr/sbin/lbt
	$(INSTALL_CONF) ./files/lbd.config $(1)/etc/config/lbd
	$(INSTALL_BIN) ./files/lbd.init $(1)/etc/init.d/lbd
endef

$(eval $(call BuildPackage,qca-whc-lbd))
