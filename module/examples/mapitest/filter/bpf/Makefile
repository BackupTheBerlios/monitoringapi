include Rules.make

CFLAGS += -static
LDFLAGS += -lpcap

EXECS := bpf_many bpf_uid bpf_ored

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc) $(LDFLAGS)

clean:
	$(call cmd,rm,$(EXECS))
