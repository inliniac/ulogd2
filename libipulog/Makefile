CC = gcc
CFLAGS = -I./include # -g

ulog_test: ulog_test.c libipulog.a
	$(CC) $(CFLAGS) -i ulog_test.c libipulog.a -o ulog_test

libipulog.o: libipulog.c
	$(CC) $(CFLAGS) -c libipulog.c -o libipulog.o

libipulog.a: libipulog.o
	ld -i libipulog.o -o libipulog.a

clean:
	rm -f ulog_test libipulog.o libipulog.a
