include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=igmpsnp
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/igmpsnp
   SECTION:=utils
   CATEGORY:=hos-app
   TITLE:=igmpsnooping
   DEPENDS:=+libpthread
endef

define Package/igmpsnp/description
	Afi Config
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

CFLAGS+=-DPC018 -Wall -Wno-unused -g -O0 -I../auteos/src/include

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
	CC="$(TARGET_CC)" \
	CFLAGS="$(CFLAGS)"
endef

define Package/igmpsnp/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/igmpsnp $(1)/sbin/
endef

$(eval $(call BuildPackage,igmpsnp))
