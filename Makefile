# Path of libipulog (from iptables)
LIBIPULOG=../libipulog

# Names of the plugins to be compiled
ULOGD_SL:=BASE OPRINT


#  Normally You should not need to change anything below
#
CC = gcc
CFLAGS = -I. -I$(LIBIPULOG)/include -g -Wall
SH_CFLAGS:=$(CFLAGS) -fPIC

SHARED_LIBS+=$(foreach T,$(ULOGD_SL),extensions/ulogd_$(T).so)

all: $(SHARED_LIBS) ulogd

$(SHARED_LIBS): %.so: %_sh.o
	ld -shared -o $@ $<

%_sh.o: %.c
	gcc $(SH_CFLAGS) -o $@ -c $<

ulogd: ulogd.c ../libipulog/libipulog.a ulogd.h
	$(CC) $(CFLAGS) -rdynamic -ldl -i ulogd.c $(LIBIPULOG)/libipulog.a -o ulogd

clean:
	rm -f ulogd extensions/*.o extensions/*.so

install: all
	mkdir -p /usr/local/lib/ulogd && cp extensions/*.so /usr/local/lib/ulogd
	cp ulogd /usr/local/sbin
	
