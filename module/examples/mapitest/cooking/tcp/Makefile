include Rules.make

CFLAGS += 

EXECS := test test_sample

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
