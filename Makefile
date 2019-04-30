VERSION=1.0

CC  := gcc
BIN := /usr/local/bin

ifeq (1, ${DEBUG})
CFLAGS=-g3 -W -Wall -Wno-unused-but-set-variable -O0 -DDEBUG=1 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
else
CFLAGS=-g3 -W -Wall -Wno-unused-but-set-variable -O4 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
endif

GLIBS=-lm -lrt -lpthread -lz
GENERIC_SRC=mem_share.h string.h sort.h list.h heap.h filereader.h hashset.h

PROGS=filterx

all: $(PROGS)

filterx: $(GENERIC_SRC) file_reader.c filterx.c
	$(CC) $(CFLAGS) -o $@ filterx.c file_reader.c.c $(GLIBS)

clean:
	rm -f *.o *.gcda *.gcno *.gcov gmon.out $(PROGS)

clear:
	rm -f *.o *.gcda *.gcno *.gcov gmon.out

install: $(PROGS)
	mkdir -p $(BIN) && cp -fvu $(PROGS) $(BIN)
