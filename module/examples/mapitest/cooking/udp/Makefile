include Rules.make

CFLAGS += 

EXECS := test test_sample test_print

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
