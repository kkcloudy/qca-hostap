include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=autossh
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/autossh
   SECTION:=utils
   CATEGORY:=hos-app
   TITLE:=Auto Establish SSH Proxy Tunnel
endef

define Package/autossh/description
	Auto Establish SSH Proxy Tunnel
endef

define Build/Compile

endef

define Package/autossh/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./src/autossh* $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/autossh.init $(1)/etc/init.d/autossh
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/autossh $(1)/etc/config/autossh
endef

$(eval $(call BuildPackage,autossh))
