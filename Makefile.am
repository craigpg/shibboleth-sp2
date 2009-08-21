AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = doc schemas configs shibsp shibd adfs util apache nsapi_shib fastcgi odbc-store memcache-store selinux

if DX_COND_doc
all-local: doxygen-doc
else
all-local:
endif

dist-hook:
	rm -rf `find $(distdir)/isapi_shib -name .svn`
	rm -rf `find $(distdir)/doc/api -name .svn`

GENFILES = shibboleth.spec pkginfo Portfile

EXTRA_DIST = $(DX_CONFIG) \
    isapi_shib \
    Shibboleth.sln \
    libtool.m4 \
    doxygen.m4 \
    acx_pthread.m4 \
    depcomp \
    config_win32.h \
    $(GENFILES) \
    $(GENFILES:%=%.in) \
    depend \
    postinstall
