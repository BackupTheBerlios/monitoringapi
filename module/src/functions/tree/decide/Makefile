MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include	\
	     -Iinclude -I../include

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

EXTRA_CFLAGS += -I$(src)/../include

obj-m += decision.o
decision-objs := decide.o decide_proxy.o

else

O_TARGET := decision.o

export-objs = decide.o
 
obj-y := decide_proxy.o	\
	 decide.o

obj-m := $(O_TARGET)
O_OBJS := $(obj-y)
M_OBJS := $(O_TARGET)

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
