include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=eag
PKG_VERSION:=2016.2.22
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)


include $(INCLUDE_DIR)/package.mk

export FILENO_PATH=$(TOPDIR)/fileno/$(TARGET_DIR_NAME)
export FILENO_BIN=$(SCRIPT_DIR)/fileno





define Package/eag
   SECTION:=utils
   CATEGORY:=hos-app
#  SECTION:=hos
#  CATEGORY:=hos
#  SUBMENU:=app
   DEPENDS:=+libpthread +libopenssl +libuci +libubus +ubus +ubusd +jshn +iptables-mod-extra +iptables-mod-ipopt \
	   +iptables-mod-iprange +iptables-mod-nat +iptables-mod-nat-extra
   TITLE:=captive-portal authentication and MAC authentication
endef

define Package/eag/description
	captive-portal authentication and MAC authentication
endef


#TARGET_CFLAGS += \
#	-I$(AUTELAN_LIBS)
#	-I$(STAGING_DIR)/usr/include \

#TARGET_LDFLAGS += \
#	-L$(STAGING_DIR)/usr/lib
define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)/src
	$(CP) ./src/* $(PKG_BUILD_DIR)/src
	rm -rf $(STAGING_DIR)/usr/include/linux
	mkdir -p $(STAGING_DIR)/usr/include/linux
	$(CP) $(TOOLCHAIN_DIR)/include/linux/netfilter $(STAGING_DIR)/usr/include/linux
	mkdir -p $(FILENO_PATH)
endef
		
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src/eag/ \
		CC="$(TARGET_CC)" \
		AR=$(TARGET_CROSS)ar \
		STAGING_DIR="$(STAGING_DIR)" \
		BUILD_DIR="$(BUILD_DIR)"
endef

define Package/eag/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/eag/eag $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/eag/eag_cli $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/eag $(1)/etc/init.d/eag
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/bash/*.sh $(1)/usr/bin
endef

$(eval $(call BuildPackage,eag))
