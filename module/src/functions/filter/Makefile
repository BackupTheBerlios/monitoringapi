MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

include $(MAPI_MODULE_DIR)/.config

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include -Iinclude

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

EXTRA_CFLAGS += -I$(src)/include

obj-$(CONFIG_MAPI_BPF_FILTER)		+= bpf.o
obj-$(CONFIG_MAPI_CACHED_BPF_FILTER)	+= cached_bpf.o
obj-$(CONFIG_MAPI_HASH)			+= hash.o
obj-$(CONFIG_MAPI_PKT_TYPE)		+= pkt_type.o

else

obj-$(CONFIG_MAPI_BPF_FILTER)		+= bpf.o
obj-$(CONFIG_MAPI_CACHED_BPF_FILTER)	+= cached_bpf.o
obj-$(CONFIG_MAPI_HASH)			+= hash.o
obj-$(CONFIG_MAPI_PKT_TYPE)		+= pkt_type.o

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
