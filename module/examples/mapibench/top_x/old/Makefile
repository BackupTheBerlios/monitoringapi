include Rules.make

CFLAGS += -static

EXEC := top_x

OBJ := subflow.o top_x.o

all: $(EXEC)

$(OBJ) : CFLAGS := $(CFLAGS) -c
$(OBJ) : %.o : %.c
	$(call cmd,cc)

$(EXEC) : CFLAGS := $(CFLAGS) -o $(EXEC)
$(EXEC): $(OBJ)
	$(call cmd,cc) -lpcap
	
clean:
	$(call cmd,rm,$(EXEC) $(OBJ))
