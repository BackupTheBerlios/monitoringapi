include Rules.make

CFLAGS +=

EXECS := test_copy test_dupl test trivial test_all_ioctls

all: $(EXECS)

mstring.o: CFLAGS := $(CFLAGS) -c

mstring.o: mstring.c
	$(call cmd,cc)
	
trivial: mstring.o

$(filter test%,$(EXECS)): % : %.c
	$(call cmd,cc)
	
$(filter trivial%,$(EXECS)): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS) mstring.o)

