MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

include $(MAPI_MODULE_DIR)/.config

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

obj-$(CONFIG_MAPI_COOK_IP) += ipv4/
obj-$(CONFIG_MAPI_COOK_UDP) += udp/
obj-$(CONFIG_MAPI_COOK_TCP) += tcp/

else

subdir-$(CONFIG_MAPI_COOK_IP) += ipv4
subdir-$(CONFIG_MAPI_COOK_UDP) += udp
subdir-$(CONFIG_MAPI_COOK_TCP) += tcp

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
