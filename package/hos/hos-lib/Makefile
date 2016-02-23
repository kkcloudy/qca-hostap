include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=hos-lib
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

HOS_LIBS=$(PKG_BUILD_DIR)
APPKEY_PATH=etc/appkey

export FILENO_PATH=$(TOPDIR)/fileno/$(TARGET_DIR_NAME)
export FILENO_BIN=$(SCRIPT_DIR)/fileno

TARGET_CFLAGS += -Wall -fPIC \
		-fexceptions -fno-omit-frame-pointer \
		-I$(HOS_LIBS) \
		-D__OPENWRT__ \
		-D__TAB_AS_SPACE=4
		
TARGET_LDFLAGS+= -shared

TARGET_CFLAGS+= -DAT_PLATFORM_$(PROFILE)
define Package/hos-lib/install/common
	$(INSTALL_DIR) $(1)/lib/
	$(INSTALL_DIR) $(1)/$(APPKEY_PATH)/
endef
####################################################################
define Package/libhos-appkey
  SECTION:=libs
  CATEGORY:=hos-lib
  TITLE:=HOS Basic library
  DEPENDS:=+libubox
endef
	
define Package/libhos-appkey/install
	$(Package/hos-lib/install/common)
	
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/appkey/libhos-appkey.so $(1)/lib/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/appkey/libappkey.limit $(1)/$(APPKEY_PATH)/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/appkey/libappkey.enum $(1)/$(APPKEY_PATH)/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/appkey/libappkey.key $(1)/$(APPKEY_PATH)/
endef

define Package/libhos-appkey/compile
	$(MAKE) -C $(PKG_BUILD_DIR)/appkey \
		CC="$(TARGET_CC)" \
		CFLAGS=" \
			$(TARGET_CFLAGS) \
			$(TARGET_CPPFLAGS) \
			-D__THIS_NAME=\\\"libappkey\\\" \
			-D__AKID_DEBUG=__libappkey_debug \
			" \
		LDFLAGS="$(TARGET_LDFLAGS)"
	$(CP) $(PKG_BUILD_DIR)/appkey/libhos-appkey.so $(STAGING_DIR)/lib
endef
####################################################################
define Package/libhos-partool
  SECTION:=libs
  CATEGORY:=hos-lib
  TITLE:=HOS Basic library
  DEPENDS:=+libubox +libhos-appkey
endef

define Package/libhos-partool/install
	$(Package/hos-lib/install/common)
	
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/partool/libhos-partool.so $(1)/lib/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/partool/libpartool.key $(1)/$(APPKEY_PATH)/
endef

define Package/libhos-partool/compile
	$(MAKE) -C $(PKG_BUILD_DIR)/partool \
		CC="$(TARGET_CC)" \
		CFLAGS=" \
			$(TARGET_CFLAGS) \
			$(TARGET_CPPFLAGS) \
			-D__THIS_NAME=\\\"libpartool\\\" \
			-D__AKID_DEBUG=__libpartool_debug \
			" \
		LDFLAGS="$(TARGET_LDFLAGS)"
	$(CP) $(PKG_BUILD_DIR)/partool/libhos-partool.so $(STAGING_DIR)/lib
endef
####################################################################
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
	
	mkdir -p $(FILENO_PATH)
endef

define Build/Configure
endef

define Build/Compile
	$(Package/libhos-appkey/compile)
	$(Package/libhos-partool/compile)
endef
####################################################################
$(eval $(call BuildPackage,libhos-appkey))
$(eval $(call BuildPackage,libhos-partool))
