include Rules.make

CFLAGS += -static #-DHAVE_PAPI_H
LDFLAGS += -lpcap -lpthread #-lpapi

EXECS := bpf_many bpf_ored pcap_many pcap_ored cached_bpf

all: $(EXECS)
	
$(EXECS): % : %.c
	$(call cmd,cc) $(LDFLAGS)

clean:
	$(call cmd,rm,$(EXECS))	
