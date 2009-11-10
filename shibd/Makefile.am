## $Id: Makefile.am 3168 2009-10-31 20:34:11Z cantor $

AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = shibd

shibd_SOURCES = shibd.cpp

shibd_LDADD = \
  $(top_builddir)/shibsp/libshibsp.la

shibd_LDFLAGS = $(XMLSEC_LIBS)

EXTRA_DIST = shibd.vcproj shibd_win32.cpp resource.h shibd.rc
