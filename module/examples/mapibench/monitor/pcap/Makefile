include Rules.make

CFLAGS += #-DSLEEP

EXECS := pcap_histo pcap_old pcap_new

all: $(EXECS)
	
$(EXECS): % : %.c
	$(call cmd,cc) -lpcap -lpthread
	
clean:
	$(call cmd,rm,$(EXECS))
		
