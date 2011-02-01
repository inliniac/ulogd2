
AM_CPPFLAGS = -I$(top_srcdir)/include $(PCAP_INC)
AM_CFLAGS = ${regular_CFLAGS}

if HAVE_PCAP

pkglibexec_LTLIBRARIES = ulogd_output_PCAP.la

ulogd_output_PCAP_la_SOURCES = ulogd_output_PCAP.c
ulogd_output_PCAP_la_LIBADD  = ${PCAP_LIB}
ulogd_output_PCAP_la_LDFLAGS = -avoid-version -module

endif
