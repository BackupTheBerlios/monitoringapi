SUBDIRS = .

INSTALL_PATH=@MAPI_MODULE_DIR@/installed/@KVERS@

all-local: kernel_module

install-exec-local: install.kernel
	$(MAKE) -C src/include install

# This must use a fully-qualified SUBDIRS path, so we can't use ${top_srcdir}
kernel_module:
	(cd $(KSRC) && $(MAKE) SUBDIRS=$(MAPI_MODULE_DIR)/src modules) || exit 1 ;

install.kernel: kernel_module
	@rm -rf $(INSTALL_PATH)
	@mkdir -p $(INSTALL_PATH)
	(cd $(KSRC) && $(MAKE) MODLIB=$(INSTALL_PATH) SUBDIRS=$(MAPI_MODULE_DIR)/src modules_install) || exit 1 ;

KSERIES=@KSERIES@

qconfig:
	$(MAKE) -C src qconfig

gconfig:
	$(MAKE) -C src gconfig

clean-local:
	rm -rf $(MAPI_MODULE_DIR)/installed
	find src -name '*.o' -or -name '.*.*.flags'		\
	         -or -name '.*.*.cmd' -or -name '*.mod.c'	\
		 | xargs rm -f

EXTRA_DIST = \
	     README 	\
	     AUTHORS 	\
	     COPYING 	\
	     Kconfig	\
	     shtool	\
	     .config
