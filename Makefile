CC = gcc -g -std=c99
CFLAGS = -Wall -Wextra -Og
SRC = traceroute.c
OBJ = traceroute.o

traceroute: traceroute.o
	$(CC) $^ -o $@

traceroute.o: traceroute.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	rm -f *.o

distclean:
	rm -f *.o traceroute

