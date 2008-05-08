AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = mdquery resolvertest

resolvertest_SOURCES = resolvertest.cpp

resolvertest_LDADD = \
	$(top_builddir)/shibsp/libshibsp.la

resolvertest_LDFLAGS = $(XMLSEC_LIBS)

mdquery_SOURCES = mdquery.cpp

mdquery_LDADD = \
	$(top_builddir)/shibsp/libshibsp.la

mdquery_LDFLAGS = $(XMLSEC_LIBS)

EXTRA_DIST = mdquery.vcproj resolvertest.vcproj
