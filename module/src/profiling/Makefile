MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

include $(MAPI_MODULE_DIR)/.config

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include -Iinclude

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

EXTRA_CFLAGS += -I$(src)/include

obj-$(CONFIG_MAPI_PROFILING) += profiling.o

profiling-objs := profile.o profile_p4.o profile_athlon.o profile_dummy.o

else

O_TARGET := profiling.o

export-objs = profile.o
 
obj-y := profile_p4.o		\
	 profile_athlon.o	\
	 profile_dummy.o	\
	 profile.o

obj-$(CONFIG_MAPI_PROFILING) := $(O_TARGET)
O_OBJS := $(obj-y)
M_OBJS := $(O_TARGET)

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
