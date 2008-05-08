## $Id: Makefile.am 2283 2007-06-01 17:35:42Z cantor $

AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = shibd

shibd_SOURCES = shibd.cpp

shibd_LDADD = \
  $(top_builddir)/shibsp/libshibsp.la

shibd_LDFLAGS = $(XMLSEC_LIBS)

EXTRA_DIST = shibd.vcproj shibd_win32.cpp resource.h shibd.rc
