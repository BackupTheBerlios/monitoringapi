include Rules.make

CFLAGS += 

EXECS := test test_all_ioctls trivial

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
