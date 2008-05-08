AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE@
plugin_LTLIBRARIES = adfs.la adfs-lite.la

adfs_la_LIBADD = \
	$(top_builddir)/shibsp/libshibsp.la

adfs_la_SOURCES = \
	adfs.cpp

adfs_lite_la_LIBADD = \
	$(top_builddir)/shibsp/libshibsp-lite.la

adfs_lite_la_SOURCES = \
	adfs.cpp

adfs_la_LDFLAGS = -module -avoid-version $(XMLSEC_LIBS)
adfs_lite_la_LDFLAGS = -module -avoid-version $(LITE_LIBS)
adfs_lite_la_CPPFLAGS = -DSHIBSP_LITE

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = adfs.vcproj adfs-lite.vcproj resource.h adfs.rc
