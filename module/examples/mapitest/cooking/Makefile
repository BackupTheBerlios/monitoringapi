include Rules.make

SUBDIRS := ipv4 udp tcp

all: $(patsubst %, _dir_%, $(SUBDIRS))

$(patsubst %, _dir_%, $(SUBDIRS)) :
	$(Q)$(MAKE) -C $(patsubst _dir_%, %, $@)

clean: $(patsubst %, _dir2_%, $(SUBDIRS))
	
$(patsubst %, _dir2_%, $(SUBDIRS)) :
	$(Q)$(MAKE) -C $(patsubst _dir2_%, %, $@) clean
