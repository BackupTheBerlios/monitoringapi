MAPI_MODULE_DIR=/current/mapi/module
KVERS=2.4.21perfcnt
KSRC=/lib/modules/2.4.21perfcnt/build

include $(MAPI_MODULE_DIR)/.config

EXTRA_CFLAGS= -finline-functions -funroll-all-loops -fomit-frame-pointer -D__NO_VERSION__ -I$(MAPI_MODULE_DIR)/src/include	\
	     -Iinclude -I../include

KSERIES=2.4

ifeq "$(KSERIES)" "2.6"

EXTRA_CFLAGS += -I$(src)/include

obj-$(CONFIG_MAPI_DECIDE_ACTION_HOOK)	+= decide_action_hook.o
obj-$(CONFIG_MAPI_DECIDE_BPF_HOOK)	+= decide_bpf_hook.o
obj-$(CONFIG_MAPI_DECIDE_TEE_HOOK)	+= decide_tee_hook.o

obj-$(CONFIG_MAPI_DECIDE) += decide/

else

export-objs = decide_action_hook.o	\
	      decide_bpf_hook.o		\
	      decide_tee_hook.o
 
obj-$(CONFIG_MAPI_DECIDE_ACTION_HOOK)	+= decide_action_hook.o
obj-$(CONFIG_MAPI_DECIDE_BPF_HOOK)	+= decide_bpf_hook.o
obj-$(CONFIG_MAPI_DECIDE_TEE_HOOK)	+= decide_tee_hook.o

subdir-$(CONFIG_MAPI_DECIDE) += decide

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

endif

# FIXME: deps
