include $(TOPDIR)/Rules.make

SUBDIRS := $(filter-out Makefile,$(shell ls))

export CC CFLAGS TOPDIR

all: $(patsubst %, _dir_%, $(SUBDIRS))

$(patsubst %, _dir_%, $(SUBDIRS)) :
	$(Q)$(MAKE) -C $(patsubst _dir_%, %, $@)

clean: $(patsubst %, _dir2_%, $(SUBDIRS))
	
$(patsubst %, _dir2_%, $(SUBDIRS)) :
	$(Q)$(MAKE) -C $(patsubst _dir2_%, %, $@) clean
