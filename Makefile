# Path of libipulog (from iptables)
LIBIPULOG=../libipulog
INCIPULOG=-I../libipulog/include

# Names of the plugins to be compiled
ULOGD_SL:=BASE OPRINT PWSNIFF LOGEMU #MYSQL

#  Normally You should not need to change anything below
#
ULOGD_VERSION=0.91

CC = gcc
CFLAGS = -I. -Wall $(INCIPULOG) -O2 -DULOGD_VERSION=\"$(ULOGD_VERSION)\" 
CFLAGS+=-g -DDEBUG

SH_CFLAGS:=$(CFLAGS) -fPIC

SHARED_LIBS+=$(foreach T,$(ULOGD_SL),extensions/ulogd_$(T).so)

all: $(SHARED_LIBS) ulogd

$(SHARED_LIBS): %.so: %_sh.o
	ld -shared -o $@ $<

%_sh.o: %.c
	$(CC) $(SH_CFLAGS) -o $@ -c $<

conffile.o: conffile.c
	$(CC) $(CFLAGS) -c $< -o $@

ulogd: ulogd.c $(LIBIPULOG) ulogd.h conffile.o
	$(CC) $(CFLAGS) -rdynamic -ldl ulogd.c -lmysqlclient conffile.o $(LIBIPULOG)/libipulog.a -o ulogd

clean:
	rm -f ulogd *.o extensions/*.o extensions/*.so

install: all
	mkdir -p /usr/local/lib/ulogd && cp extensions/*.so /usr/local/lib/ulogd
	cp ulogd /usr/local/sbin
	
