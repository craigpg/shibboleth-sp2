AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE@
plugin_LTLIBRARIES = odbc-store.la

AM_CFLAGS = $(ODBC_CFLAGS)
AM_CXXFLAGS = $(ODBC_CFLAGS)

odbc_store_la_LIBADD = \
	$(ODBC_LIBS)

odbc_store_la_SOURCES = \
	odbc-store.cpp

odbc_store_la_LDFLAGS = -module -avoid-version $(XMLSEC_LIBS)

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = odbc-store.vcproj odbc-store.rc resource.h
