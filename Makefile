CC = gcc
CFLAGS = -Wall -Werror -pedantic -g
FLAGS = *.c -lpcap
PROG = dns-monitor
LOGIN = xpriby22
FILES = *.c *.h Makefile README manual.pdf

all:
	$(CC) $(CFLAGS) $(FLAGS) -lresolv -o $(PROG) 2>/dev/null || $(CC) $(CFLAGS) $(FLAGS) -o $(PROG)

clean:
	rm -f $(PROG)

pack: all clean
	tar cvf $(LOGIN).tar $(FILES_TEST)
