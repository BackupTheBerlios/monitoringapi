MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

include $(MAPI_MODULE_DIR)/.config

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

obj-$(CONFIG_MAPI_BYTES_IN_INTERVAL)	+= bytes_in_int.o		
obj-$(CONFIG_MAPI_COUNT_BYTES)		+= count_bytes.o	
obj-$(CONFIG_MAPI_COUNT_PACKETS)	+= count_packets.o	
obj-$(CONFIG_MAPI_NETDEV_STATS)		+= netdev_stats.o	
obj-$(CONFIG_MAPI_PACKET_DISTRIBUTION)	+= packet_dist.o
obj-$(CONFIG_MAPI_PACKETS_IN_INTERVAL)	+= packets_in_int.o

else

obj-$(CONFIG_MAPI_BYTES_IN_INTERVAL)	+= bytes_in_int.o		
obj-$(CONFIG_MAPI_COUNT_BYTES)		+= count_bytes.o	
obj-$(CONFIG_MAPI_COUNT_PACKETS)	+= count_packets.o	
obj-$(CONFIG_MAPI_NETDEV_STATS)		+= netdev_stats.o	
obj-$(CONFIG_MAPI_PACKET_DISTRIBUTION)	+= packet_dist.o
obj-$(CONFIG_MAPI_PACKETS_IN_INTERVAL)	+= packets_in_int.o

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
