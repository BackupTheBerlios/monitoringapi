include Rules.make

CFLAGS += 

EXECS := test 

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
