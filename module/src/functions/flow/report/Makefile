MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include	\
	     -Iinclude -I ../include -I ../subflow/include

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

EXTRA_CFLAGS += -I$(src)/include -I$(src)/../include -I$(src)/../subflow/include

obj-m += netflow.o
obj-m += flow_report.o

else

O_TARGET := freport.o

obj-y := netflow.o	\
	 flow_report.o

obj-m := $(O_TARGET)
O_OBJS := $(obj-y)
M_OBJS := $(O_TARGET)

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
