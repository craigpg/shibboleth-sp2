AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = doc schemas configs shibsp shibd adfs util apache nsapi_shib fastcgi odbc-store memcache-store selinux

if DX_COND_doc
all-local: shibboleth.spec pkginfo doxygen-doc
APIDOCS = doc/api
else
all-local: shibboleth.spec pkginfo
endif

install-data-hook:
	rm -rf $(DESTDIR)$(datadir)/doc/@PACKAGE@/api
	cp -r doc/api $(DESTDIR)$(datadir)/doc/@PACKAGE@

dist-hook:
	rm -rf `find $(distdir)/isapi_shib -name .svn`
	rm -rf `find $(distdir)/doc/api -name .svn`

shibboleth.spec: shibboleth.spec.in Makefile
	rm -f $@.tmp
	sed < $@.in > $@.tmp \
	    -e 's:@-VERSION-@:${VERSION}:'
	mv $@.tmp $@

pkginfo: pkginfo.in Makefile
	rm -f $@.tmp
	sed < $@.in > $@.tmp \
	    -e 's:@-VERSION-@:${VERSION}:'
	mv $@.tmp $@

EXTRA_DIST = $(DX_CONFIG) \
    $(APIDOCS) \
    isapi_shib \
    Shibboleth.sln \
    libtool.m4 \
    doxygen.m4 \
    acx_pthread.m4 \
    depcomp \
    config_win32.h \
    shibboleth.spec.in \
    shibboleth.spec \
    pkginfo.in \
    pkginfo \
    depend \
    postinstall

DISTCLEANFILES = shibboleth.spec pkginfo
