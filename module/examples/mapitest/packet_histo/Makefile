include Rules.make

CFLAGS += 

EXECS := histogram

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
