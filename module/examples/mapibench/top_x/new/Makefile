include Rules.make

CFLAGS += -static

EXEC := top_x

OBJ := subflow.o top_x.o filter.o sort.o

all: $(EXEC)

$(OBJ) : CFLAGS := $(CFLAGS) -c
$(OBJ) : %.o : %.c
	$(call cmd,cc)

$(EXEC) : CFLAGS := $(CFLAGS) -o $(EXEC)
$(EXEC): $(OBJ)
	$(call cmd,cc) -lpcap -lm
	
clean:
	$(call cmd,rm,$(EXEC) $(OBJ))
