include Rules.make

CFLAGS += #-DSLEEP

EXECS := flow_report flow_send

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
