include Rules.make

CFLAGS += -static
LDFLAGS += -lpcap

EXECS := cbpf_many cbpf_ored cbpf_uid

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc) $(LDFLAGS)

clean:
	$(call cmd,rm,$(EXECS))
