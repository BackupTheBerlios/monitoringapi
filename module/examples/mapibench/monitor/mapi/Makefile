include Rules.make

CFLAGS += #-DSLEEP

EXECS := mapi_old_threads mapi_old_poll mapi_old_mmap mapi_old_mmap_all mapi_new

all: $(EXECS)

mapi_basic.o: CFLAGS := $(CFLAGS) -c
	
mapi_basic.o: mapi_basic.c
	$(call cmd,cc)
	
$(EXECS): mapi_basic.o

$(EXECS): % : %.c
	$(call cmd,cc) -lpcap -lpthread

clean:
	$(call cmd,rm,$(EXECS) mapi_basic.o)
		
