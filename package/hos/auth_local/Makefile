include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=auth_local
PKG_VERSION:=2016.2.23
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

export FILENO_PATH=$(TOPDIR)/fileno/$(TARGET_DIR_NAME)
export FILENO_BIN=$(SCRIPT_DIR)/fileno





define Package/auth_local
	SECTION:=apps
	CATEGORY:=hos-app
   	TITLE:=authentication local support
	DEPENDS:=+libpthread +libxml2 +libz +libcgic
endef

define Package/auth_local/description
	internal portal authentication and internal data base 
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)/src
	$(CP) ./src/* $(PKG_BUILD_DIR)/src
	mkdir -p $(FILENO_PATH)
endef

#TARGET_CFLAGS += \
#	-I$(AUTELAN_LIBS)
#	-I$(STAGING_DIR)/usr/include \

#TARGET_LDFLAGS += \
#	-L$(STAGING_DIR)/usr/lib


define Build/Compile
	
	RANLIB=$(TARGET_CROSS)ranlib \
	OBJCOPY=$(TARGET_CROSS)objcopy \
	$(MAKE) -C $(PKG_BUILD_DIR)/src/portal \
	CC="$(TARGET_CC)" \
	AR=$(TARGET_CROSS)ar \
	AUTELAN_LIBS="$(AUTELAN_LIBS)" \
	STAGING_DIR="$(STAGING_DIR)"
endef

define Package/auth_local/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/portal/userm_cli $(1)/sbin/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/portal/libcgic.so* $(1)/usr/lib/
	mkdir -p $(1)/www/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/portal/*.cgi $(1)/www/cgi-bin
	$(CP) $(PKG_BUILD_DIR)/src/www/*.html $(1)/www/
	$(INSTALL_DIR) $(1)/etc/init.d
endef
$(eval $(call BuildPackage,auth_local))
