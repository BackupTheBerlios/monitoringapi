MAPI_EXAMPLES := /current/mapi/module/examples

include Makefile.build

INCLUDE_DIR_A := $(MAPI_EXAMPLES)/include
INCLUDE_DIR_B := ./include

CC     := gcc
CFLAGS := -O2 -Wall

CFLAGS += -I$(INCLUDE_DIR_A) -I$(INCLUDE_DIR_B)

.DELETE_ON_ERROR:
.PHONY: all clean
