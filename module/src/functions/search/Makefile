MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

include $(MAPI_MODULE_DIR)/.config

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

obj-$(CONFIG_MAPI_EXB) 			+= exb.o
obj-$(CONFIG_MAPI_SUBSTRING_SEARCH)	+= substring_search.o

else

obj-$(CONFIG_MAPI_EXB) 			+= exb.o
obj-$(CONFIG_MAPI_SUBSTRING_SEARCH)	+= substring_search.o

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
