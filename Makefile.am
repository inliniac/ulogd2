
AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

man_MANS = ulogd.8

EXTRA_DIST = $(man_MANS)

INCLUDES = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = src input filter output
DIST_SUBDIRS = src input filter output

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
