CC = gcc
LD = ld

CFLAGS = -Wall -c -O
LDFLAGS=

OBJS = main.o 

.PHONY: all clean

keccak: keccak.o $(OBJS)
	$(CC) -o $@ $^

keccak_tiny: keccak_tiny.o $(OBJS)
	$(CC) -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	-$(RM) *.o
	-$(RM) keccak
	-$(RM) keccak_tiny
