MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include

include $(MAPI_MODULE_DIR)/.config

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

obj-$(CONFIG_MAPI) += pf_mapi.o
pf_mapi-objs := register.o receive.o list.o init.o af_mapi.o nommap.o mmap.o

obj-$(CONFIG_MAPI) += profiling/
obj-$(CONFIG_MAPI) += misc/
obj-$(CONFIG_MAPI) += functions/

else

O_TARGET := pf_mapi.o

export-objs = register.o	\
	      receive.o		\
	      list.o		\
	      init.o		\
	      nommap.o		\
	      mmap.o		\
	      af_mapi.o
 
obj-y := af_mapi.o	\
	 register.o	\
	 receive.o	\
	 list.o		\
	 init.o		\
	 nommap.o	\
	 mmap.o

obj-$(CONFIG_MAPI) := $(O_TARGET)
O_OBJS := $(obj-y)
M_OBJS := $(O_TARGET)

subdir-$(CONFIG_MAPI) += profiling	\
	    		 functions	\
	    		 misc

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

ifeq "$(KSERIES)" "2.6"

qconfig:
	(cd $(KSRC)/scripts/kconfig && ./qconf $(MAPI_MODULE_DIR)/Kconfig) || exit 1 ;
	mv $(KSRC)/scripts/kconfig/.config $(MAPI_MODULE_DIR)/.config

gconfig:
	(cd $(KSRC)/scripts/kconfig && ./gconf $(MAPI_MODULE_DIR)/Kconfig) || exit 1 ;
	mv $(KSRC)/scripts/kconfig/.config $(MAPI_MODULE_DIR)/.config

else

qconfig:
	@echo "Not supported in Linux 2.4. Edit .config manually!"

gconfig:
	@echo "Not supported in Linux 2.4. Edit .config manually!"

endif

# FIXME: deps
