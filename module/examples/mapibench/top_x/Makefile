include Rules.make

SUBDIRS = old new

export TOPDIR CC CFLAGS

all: $(patsubst %, _dir_%, $(SUBDIRS))

$(patsubst %, _dir_%, $(SUBDIRS)) :
	$(Q)$(MAKE) -C $(patsubst _dir_%, %, $@)

clean: $(patsubst %, _dir2_%, $(SUBDIRS))
	
$(patsubst %, _dir2_%, $(SUBDIRS)) :
	$(Q)$(MAKE) -C $(patsubst _dir2_%, %, $@) clean
