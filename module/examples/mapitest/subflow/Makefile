include Rules.make

CFLAGS +=

EXECS := test_async test_blocking measure_async test_all_ioctls

all: $(EXECS)

sig_int.o: CFLAGS := $(CFLAGS) -c

sig_int.o: sig_int.c
	$(call cmd,cc)

$(filter-out test_all_ioctls,$(EXECS)): sig_int.o

$(filter-out test_all_ioctls,$(EXECS)): % : %.c
	$(call cmd,cc)
	
test_all_ioctls: % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS) sig_int.o)
