CC = gcc
CFLAGS = -Wall -Werror -pedantic -g
FLAGS = string_t.c arg_parser.c file_records_mgmt.c -lpcap
PROG = dns-monitor

all:
	$(CC) $(CFLAGS) $(PROG).c $(FLAGS) -lresolv -o $(PROG) 2>/dev/null || $(CC) $(CFLAGS) $(PROG).c $(FLAGS) -o $(PROG)

clean:
	rm -f $(PROG)
