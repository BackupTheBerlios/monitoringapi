include Rules.make

CFLAGS += 

EXECS := test test_async test_all_ioctls

all: $(EXECS)

$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
