MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

include $(MAPI_MODULE_DIR)/.config

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include	\
	     -Iinclude

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

EXTRA_CFLAGS += -I$(src)/include

obj-$(CONFIG_MAPI_LOGGING) += log.o
log-objs := logging.o fakepcap.o file_ops.o

else

O_TARGET := log.o

obj-y := logging.o	\
	 fakepcap.o	\
	 file_ops.o

obj-$(CONFIG_MAPI_LOGGING) := $(O_TARGET)
O_OBJS := $(obj-y)
M_OBJS := $(O_TARGET)

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
