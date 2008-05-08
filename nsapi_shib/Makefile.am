AUTOMAKE_OPTIONS = foreign

if BUILD_NSAPI
nsapi_shibdir = $(libdir)/@PACKAGE@
nsapi_shib_LTLIBRARIES = nsapi_shib.la
nsapi_shib_la_SOURCES = nsapi_shib.cpp
nsapi_shib_la_CXXFLAGS = $(NSAPI_INCLUDE)
nsapi_shib_la_LDFLAGS = $(LITE_LIBS) -module -avoid-version
nsapi_shib_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la

install-exec-hook:
	for la in $(nsapi_shib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(nsapi_shibdir)/$$la ; done

endif

EXTRA_DIST = nsapi_shib.vcproj resource.h nsapi_shib.rc nsapi_shib.cpp
