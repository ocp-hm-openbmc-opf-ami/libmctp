ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libmctp.la
libmctp_la_SOURCES = core.c encode_request.c encode_response.c decode_request.c decode_response.c alloc.c log.c \
		     libmctp-alloc.h libmctp-log.h \
		     libmctp-cmds.h libmctp-encode-request.h libmctp-encode-response.h libmctp-decode-request.h libmctp-decode-response.h libmctp-vdpci.h
include_HEADERS = libmctp.h

if LIBMCTP_BINDING_serial
libmctp_la_SOURCES += serial.c
include_HEADERS += libmctp-serial.h
endif

if LIBMCTP_BINDING_astlpc
libmctp_la_SOURCES += astlpc.c
include_HEADERS += libmctp-astlpc.h
endif

if LIBMCTP_BINDING_astpcie
libmctp_la_SOURCES += astpcie.c
include_HEADERS += libmctp-astpcie.h
endif

if LIBMCTP_BINDING_smbus
libmctp_la_SOURCES += smbus.c
include_HEADERS += libmctp-smbus.h
endif

if LIBMCTP_BINDING_asti3c
libmctp_la_SOURCES += asti3c.c
include_HEADERS += libmctp-asti3c.h
endif

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	mctp-demux.service
endif

pkgconfig_DATA = libmctp.pc

if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)

TESTS = $(check_PROGRAMS)

check_PROGRAMS = tests/test_eid tests/test_seq tests/test_bridge \
		 tests/test_astpcie tests/test_cmds tests/test_asti3c
# We set a global LDADD here, as there's no way to specify it for all
# tests. This means other targets' LDADDs need to be overridden.
LDADD = tests/libtest-utils.a libmctp.la

noinst_LIBRARIES = tests/libtest-utils.a

tests_libtest_utils_a_SOURCES = tests/test-utils.c tests/test-utils.h
