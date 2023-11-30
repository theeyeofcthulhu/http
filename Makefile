CC=gcc
CFLAGS=-Wall -Wextra -std=c11 -pedantic -ggdb -D_POSIX_C_SOURCE=20080901
LDLIBS=

SRC=tcp.c request.c url.c handler.c
HDR=request.h url.h handler.h
OBJ=$(SRC:.c=.o)
EXE=tcp

.PHONY: all clean

all: $(EXE)

clean:
	rm -f $(OBJ) $(EXE)

$(OBJ): %.o: %.c $(HDR)
	$(CC) $(CFLAGS) -o $@ -c $<

$(EXE): $(OBJ)
	$(CC) -o $@ $^ $(LDLIBS)
