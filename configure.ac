dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.50])
AC_INIT([ulogd], [2.0.0beta4])

AM_INIT_AUTOMAKE([-Wall foreign dist-bzip2 1.10b])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Checks for programs.
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

dnl Checks for libraries.
AC_SEARCH_LIBS([dlopen], [dl], [libdl_LIBS="$LIBS"; LIBS=""])
AC_SUBST([libdl_LIBS])
AC_CHECK_HEADER(pcap.h,HAVE_PCAP_H=true)

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_SYS_LARGEFILE

dnl Checks for library functions.
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(socket strerror)

regular_CFLAGS="-Wall -Wextra -Wno-unused-parameter"
AC_SUBST([regular_CFLAGS])

dnl Check for the right nfnetlink version
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 0.0.39])
PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 0.0.95])
PKG_CHECK_MODULES([LIBNETFILTER_LOG], [libnetfilter_log >= 1.0.0])

CT_CHECK_POSTGRES_DB()
AM_CONDITIONAL(HAVE_PGSQL, test "x$PQLIBPATH" != "x")

CT_CHECK_MYSQL_DB()
AM_CONDITIONAL(HAVE_MYSQL, test "x$MYSQL_LIB" != "x")

PKG_CHECK_MODULES([libsqlite3], [sqlite3], [], [:])
AM_CONDITIONAL([HAVE_SQLITE3], [test -n "$libsqlite3_LIBS"])

CT_CHECK_DBI()
AM_CONDITIONAL(HAVE_DBI, test "x$DBI_LIB" != "x")

CT_CHECK_PCAP()
AM_CONDITIONAL(HAVE_PCAP, test "x$HAVE_PCAP_LIB" != "x")


dnl AC_SUBST(DATABASE_DIR)
dnl AC_SUBST(DATABASE_LIB)
dnl AC_SUBST(DATABASE_LIB_DIR)
dnl AC_SUBST(DB_DEF)
dnl AC_SUBST(EXTRA_MYSQL_DEF)
dnl AC_SUBST(EXTRA_PGSQL_DEF)

dnl AC_SUBST(DATABASE_DRIVERS)
dnl AC_SUBST(HAVE_PCAP_H)

dnl AM_CONDITIONAL(HAVE_MYSQL, test x$mysqldir != x)
dnl AM_CONDITIONAL(HAVE_PGSQL, test x$pgsqldir != x)

AC_CONFIG_FILES(include/Makefile include/ulogd/Makefile include/libipulog/Makefile \
	  libipulog/Makefile \
	  input/Makefile input/packet/Makefile input/flow/Makefile \
	  filter/Makefile filter/raw2packet/Makefile filter/packet2flow/Makefile \
	  output/Makefile output/pcap/Makefile output/mysql/Makefile output/pgsql/Makefile output/sqlite3/Makefile \
	  output/dbi/Makefile \
	  src/Makefile Makefile Rules.make)
AC_OUTPUT
