include Rules.make

CFLAGS +=

EXECS := mmap_reader

all: $(EXECS)
	
$(EXECS): % : %.c
	$(call cmd,cc)

clean:
	$(call cmd,rm,$(EXECS))
		
