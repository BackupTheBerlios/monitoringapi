include Rules.make

CFLAGS += -DDEBUG -static

EXECS := pcap_test

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc) -lpcap

clean:
	$(call cmd,rm,$(EXECS))
