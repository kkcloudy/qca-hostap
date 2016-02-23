include $(TOPDIR)/rules.mk

PKG_NAME:=auteos
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)/src

include $(INCLUDE_DIR)/package.mk

AUTEOS_LIBS=$(PKG_BUILD_DIR)


TARGET_CFLAGS += -Wall -fPIC \
		-fexceptions -fno-omit-frame-pointer \
		-I$(AUTEOS_LIBS) \
		-D__OPENWRT__ \
		-D__TAB_AS_SPACE=4
		
TARGET_LDFLAGS+= -shared
define Package/auteos/install/common
	$(INSTALL_DIR) $(1)/lib

endef
####################################################################
define Package/libauteos
  SECTION:=libs
  CATEGORY:=hos-lib
  TITLE:=HOS Basic library

endef
	
define Package/libauteos/install
	$(Package/auteos/install/common)
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/libauteos.so $(1)/lib/
endef

define Package/libauteos/compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src -f Makefile.ap83 \
		CC="$(TARGET_CC)" \
		CFLAGS=" \
			$(TARGET_CFLAGS) \
			$(TARGET_CPPFLAGS) \
			" \
		LDFLAGS="$(TARGET_LDFLAGS)"
	$(CP) $(PKG_BUILD_DIR)/src/libauteos.so $(STAGING_DIR)/lib
endef
####################################################################
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)

endef

define Build/Configure
endef

define Build/Compile
	$(Package/libauteos/compile)

endef
####################################################################
$(eval $(call BuildPackage,libauteos))


