include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=relay
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/relay
	SUBMENU:=Other modules
	TITLE:= relay module
	DEPENDS:=@LINUX_3_4
	FILES:=$(PKG_BUILD_DIR)/*.$(LINUX_KMOD_SUFFIX)
	KCONFIG:=
endef

define KernelPackage/relay/description	
	Kernel module to packet relay
endef

EXTRA_KCONFIG:= \
	CONFIG_RELAY=m

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


$(eval $(call KernelPackage,relay))
