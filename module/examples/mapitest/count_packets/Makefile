include Rules.make

CFLAGS += #-DSLEEP

EXECS := test test_uid test_all_ioctls trivial

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
