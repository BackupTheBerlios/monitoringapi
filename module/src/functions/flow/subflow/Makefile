MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include	\
	     -Iinclude -I../include

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

EXTRA_CFLAGS += -I$(src)/include -I$(src)/../include

obj-m := subflow.o	
obj-m := hashtable.o	
obj-m := timers.o	
obj-m := proc.o		
obj-m := key.o	
obj-m := caches.o

else

O_TARGET := hiersubflow.o

export-objs = caches.o
 
obj-y := subflow.o	\
	 hashtable.o	\
	 timers.o	\
	 proc.o		\
	 key.o		\
	 caches.o

obj-m := $(O_TARGET)
O_OBJS := $(obj-y)
M_OBJS := $(O_TARGET)

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
