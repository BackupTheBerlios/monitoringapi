MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

include $(MAPI_MODULE_DIR)/.config

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

obj-$(CONFIG_MAPI_BAND_METER)	+= band_meter.o 
obj-$(CONFIG_MAPI_METER)	+= meter.o

else

obj-$(CONFIG_MAPI_BAND_METER)	+= band_meter.o 
obj-$(CONFIG_MAPI_METER)	+= meter.o

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
