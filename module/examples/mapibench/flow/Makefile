include Rules.make

CFLAGS +=

EXECS := flow_mapi flow_pcap

all: $(EXECS)
	
$(EXECS): % : %.c
	$(call cmd,cc) -lpcap -lpthread

clean:
	$(call cmd,rm,$(EXECS))	
