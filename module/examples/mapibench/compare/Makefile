include Rules.make

CFLAGS += -static #-DSLEEP

EXECS := mmap_get pcap_get

all: $(EXECS)
	
$(EXECS): % : %.c
	$(call cmd,cc) -lpcap	

clean:
	$(call cmd,rm,$(EXECS))	
