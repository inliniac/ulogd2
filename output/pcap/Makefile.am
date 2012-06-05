
AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

if HAVE_PCAP

pkglib_LTLIBRARIES = ulogd_output_PCAP.la

ulogd_output_PCAP_la_SOURCES = ulogd_output_PCAP.c
ulogd_output_PCAP_la_LIBADD  = ${libpcap_LIBS}
ulogd_output_PCAP_la_LDFLAGS = -avoid-version -module

endif
