MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

include $(MAPI_MODULE_DIR)/.config

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include	\
	     -Iinclude

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

EXTRA_CFLAGS += -I$(src)/include

obj-$(CONFIG_MAPI_PRINT_ETHER)	+= print_ether.o
obj-$(CONFIG_MAPI_PRINT_IP)	+= print_ip.o
obj-$(CONFIG_MAPI_PRINT_UDP)	+= print_udp.o
obj-$(CONFIG_MAPI_PRINT_TCP)	+= print_tcp.o

else

obj-$(CONFIG_MAPI_PRINT_ETHER)	+= print_ether.o
obj-$(CONFIG_MAPI_PRINT_IP)	+= print_ip.o
obj-$(CONFIG_MAPI_PRINT_UDP)	+= print_udp.o
obj-$(CONFIG_MAPI_PRINT_TCP)	+= print_tcp.o

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
