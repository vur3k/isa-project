CC = gcc
CFLAGS = -Wall -Werror -pedantic -g
FLAGS = src/*.c -lpcap
PROG = dns-monitor
LOGIN = xpriby22
FILES = src/* tests/* Makefile README LICENSE manual.pdf

all:
	$(CC) $(CFLAGS) $(FLAGS) -lresolv -o $(PROG) 2>/dev/null || $(CC) $(CFLAGS) $(FLAGS) -o $(PROG)

clean:
	rm -f $(PROG)

pack: all clean
	tar cvf $(LOGIN).tar $(FILES)
