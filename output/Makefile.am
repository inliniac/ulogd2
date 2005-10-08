
SUBDIRS = pcap

INCLUDES = $(all_includes) -I$(top_srcdir)/include
LIBS=

pkglib_LTLIBRARIES = ulogd_output_LOGEMU.la ulogd_output_SYSLOG.la # ulogd_output_OPRINT.la

ulogd_output_LOGEMU_la_SOURCES = ulogd_output_LOGEMU.c
ulogd_output_LOGEMU_la_LDFLAGS = -module

ulogd_output_SYSLOG_la_SOURCES = ulogd_output_SYSLOG.c
ulogd_output_SYSLOG_la_LDFLAGS = -module

#ulogd_OPRINT_la_SOURCES = ulogd_output_OPRINT.c
#ulogd_OPRINT_la_LDFLAGS = -module


