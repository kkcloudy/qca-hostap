include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=hos-app
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

HOS_LIBS=$(BUILD_DIR)/hos-lib

export FILENO_PATH=$(TOPDIR)/fileno/$(TARGET_DIR_NAME)
export FILENO_BIN=$(SCRIPT_DIR)/fileno

TARGET_CFLAGS += -Wall \
		-fexceptions -fno-omit-frame-pointer \
		-I$(HOS_LIBS) \
		-D__OPENWRT__ \
		-D__TAB_AS_SPACE=4 
		
TARGET_CFLAGS+= -DAT_PLATFORM_$(PROFILE)
		
#TARGET_LDFLAGS+= -L$(STAGING_DIR)/lib -Wl,-rpath,$(STAGING_DIR)/lib
TARGET_LDFLAGS+= -L$(STAGING_DIR)/lib

APPKEY_PATH=etc/appkey
BACKTRACE_PATH=usr/app/backtrace

define Package/hos-app/install/common
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/$(BACKTRACE_PATH)/
	$(INSTALL_DIR) $(1)/$(APPKEY_PATH)/
endef
####################################################################
define Package/hos-appkey
  SECTION:=apps
  CATEGORY:=hos-app
  TITLE:=HOS Basic App
  DEPENDS:=+libubacktrace +libhos-appkey +libubox
endef

define Package/hos-appkey/install
	$(Package/hos-app/install/common)
	$(INSTALL_DIR) $(1)/$(BACKTRACE_PATH)/appkey/
	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/appkey/appkey $(1)/usr/bin
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/appkey/appkey.key $(1)/$(APPKEY_PATH)/
endef

define Package/hos-appkey/compile
	$(MAKE) -C $(PKG_BUILD_DIR)/appkey \
		CC="$(TARGET_CC)" \
		CFLAGS=" \
			$(TARGET_CFLAGS) \
			$(TARGET_CPPFLAGS) \
			-D__THIS_NAME=\\\"appkey\\\" \
			-D__AKID_DEBUG=__appkey_debug \
			" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef
####################################################################
define Package/hos-btt
  SECTION:=apps
  CATEGORY:=hos-app
  TITLE:=hos Basic App
  DEPENDS:=+libubacktrace +libhos-appkey +libubox
endef

define Package/hos-btt/install
	$(Package/hos-app/install/common)
	$(INSTALL_DIR) $(1)/$(BACKTRACE_PATH)/btt/
	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/btt/btt $(1)/usr/bin
endef

define Package/hos-btt/compile
	$(MAKE) -C $(PKG_BUILD_DIR)/btt \
		CC="$(TARGET_CC)" \
		CFLAGS=" \
			$(TARGET_CFLAGS) \
			$(TARGET_CPPFLAGS) \
			-D__THIS_NAME=\\\"btt\\\" \
			-D__AKID_DEBUG=__btt_debug \
			" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef
####################################################################
define Package/hos-partool
  SECTION:=apps
  CATEGORY:=hos-app
  TITLE:=HOS Basic App
  DEPENDS:=+libubacktrace +libhos-appkey +libhos-partool +libubox
endef

define Package/hos-partool/install
	$(Package/hos-app/install/common)
	$(INSTALL_DIR) $(1)/$(BACKTRACE_PATH)/partool/
	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/partool/partool $(1)/usr/bin
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/partool/partool.key $(1)/$(APPKEY_PATH)/
endef

define Package/hos-partool/compile
	$(MAKE) -C $(PKG_BUILD_DIR)/partool \
		CC="$(TARGET_CC)" \
		CFLAGS=" \
			$(TARGET_CFLAGS) \
			$(TARGET_CPPFLAGS) \
			-D__THIS_NAME=\\\"partool\\\" \
			-D__AKID_DEBUG=__partool_debug \
			-DPART_RW_MTD \
			" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef
####################################################################
define Package/hos-um
  SECTION:=apps
  CATEGORY:=hos-app
  TITLE:=HOS Basic App
  DEPENDS:=+libubacktrace +libhos-appkey +libuci +libubus +libubox +libblobmsg-json +libpthread
endef

define Package/hos-um/install
	$(Package/hos-app/install/common)
	$(INSTALL_DIR) $(1)/$(BACKTRACE_PATH)/um/
	$(INSTALL_DIR) $(1)/etc/init.d

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/um/um $(1)/usr/bin
	$(INSTALL_BIN) ./files/um $(1)/etc/init.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/um/um.key $(1)/$(APPKEY_PATH)/
endef

define Package/hos-um/compile
	$(MAKE) -C $(PKG_BUILD_DIR)/um \
		CC="$(TARGET_CC)" \
		CFLAGS=" \
			$(TARGET_CFLAGS) \
			$(TARGET_CPPFLAGS) \
			-D__THIS_NAME=\\\"um\\\" \
			-D__AKID_DEBUG=__um_debug \
			" \
		LDFLAGS="$(TARGET_LDFLAGS)"
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
	$(Package/hos-btt/compile)
	$(Package/hos-appkey/compile)
	$(Package/hos-partool/compile)
	$(Package/hos-um/compile)
endef
####################################################################
$(eval $(call BuildPackage,hos-btt))
$(eval $(call BuildPackage,hos-appkey))
$(eval $(call BuildPackage,hos-partool))
$(eval $(call BuildPackage,hos-um))

