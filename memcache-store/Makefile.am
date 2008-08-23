AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE@
plugin_LTLIBRARIES = memcache-store.la

AM_CFLAGS = $(MEMCACHED_CFLAGS)
AM_CXXFLAGS = $(MEMCACHED_CFLAGS)

memcache_store_la_LIBADD = \
	$(MEMCACHED_LIBS)

memcache_store_la_SOURCES = \
	memcache-store.cpp

memcache_store_la_LDFLAGS = -module -avoid-version $(XMLSEC_LIBS)

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = memcache-store.vcproj memcache-store.rc resource.h
