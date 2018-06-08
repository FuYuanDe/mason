include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=capture
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/capture
	SUBMENU:=Other modules
	TITLE:= capture module
	DEPENDS:=@LINUX_3_4
	FILES:=$(PKG_BUILD_DIR)/*.$(LINUX_KMOD_SUFFIX)
	KCONFIG:=
endef

define KernelPackage/capture/description	
	Kernel module to packet capture
endef

EXTRA_KCONFIG:= \
	CONFIG_CAPTURE=m

EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG)))) \

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
	$(MAKE_OPTS) \
	modules
endef

define Package/capture/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(CP) $(PKG_BUILD_DIR)/files/capture.init $(1)/etc/init.d/
endef

#define Package/capture/install
#	$(CP) ./files/capture.init $(1)/etc/init.d/
#	$(CP) $(PKG_BUILD_DIR)/capture $(1)/etc/init.d/
#	$(INSTALL_DIR) $(1)/etc/init./d
#	$(CP) ./files/capture.init $(1)/etc/init.d/
#endef

define Package/postinst
#!/bin/sh
cd /lib/modules/`uname -r`/
if [ -f capture.ko ];then
	insmod capture.ko
fi
endef

$(eval $(call KernelPackage,capture))
