include Rules.make

CFLAGS += -static
LDFLAGS += -lpcap

EXECS := filter_many filter_ored

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc) $(LDFLAGS)

clean:
	$(call cmd,rm,$(EXECS))
