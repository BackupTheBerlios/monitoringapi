include Rules.make

CFLAGS += #-DSLEEP

EXECS := test test_alone test_simple test_action

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
