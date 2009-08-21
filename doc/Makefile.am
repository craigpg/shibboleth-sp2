AUTOMAKE_OPTIONS = foreign

pkgdocdir = $(datadir)/doc/@PACKAGE@-@PACKAGE_VERSION@

install-data-hook:
	cp -r api $(DESTDIR)$(pkgdocdir)
	rm -rf `find $(DESTDIR)$(pkgdocdir)/api -name .svn`

docfiles = \
	CREDITS.txt \
	LICENSE.txt \
	NOTICE.txt \
	README.txt \
	RELEASE.txt \
	FASTCGI.LICENSE \
	OPENSSL.LICENSE \
	LOG4CPP.LICENSE \
	main.css \
	logo.jpg
	
pkgdoc_DATA = $(docfiles)

EXTRA_DIST = $(docfiles) api
