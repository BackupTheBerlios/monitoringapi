include Rules.make

CFLAGS += 

EXECS := test test_async

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
