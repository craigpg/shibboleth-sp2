## $Id: Makefile.am 3168 2009-10-31 20:34:11Z cantor $ 

AUTOMAKE_OPTIONS = foreign

pkglibdir = ${libdir}/@PACKAGE@
pkglogdir = ${localstatedir}/log/@PACKAGE@
pkgdocdir = $(datadir)/doc/@PACKAGE@-@PACKAGE_VERSION@
shirelogdir = ${localstatedir}/log/httpd
pkgxmldir = $(datadir)/xml/@PACKAGE@
pkgrundir = $(localstatedir)/run/@PACKAGE@
pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	shibd-redhat \
	shibd-suse \
	shibd-debian \
	shibd-osx.plist \
	apache.config \
	apache2.config \
	apache22.config \
	keygen.sh \
	metagen.sh \
	upgrade.xsl

# The config files are installed "special".  Unlike the entries in
# pkgsysconf_DATA, these files are installed as "foo.dist" and only
# installed as "foo" if "foo" does not already exist.  In other words,
# the config files will not overwrite existing versions.
BUILTCONFIGFILES = \
	native.logger \
	shibd.logger

# While BUILTCONFIGFILES are processed, these are not; so we should pull
# them from SRCDIR.
CONFIGFILES = \
	shibboleth2.xml \
	attribute-map.xml \
	attribute-policy.xml \
	example-metadata.xml \
	console.logger \
	syslog.logger \
	accessError.html \
	sessionError.html \
	metadataError.html \
	bindingTemplate.html \
	discoveryTemplate.html \
    postTemplate.html \
	localLogout.html \
	globalLogout.html \
	partialLogout.html \
	sslError.html

#
# Some of these need building
#
do-build-file:
	rm -f ${FILE}.tmp
	sed < ${srcdir}/${FILE}.in > ${FILE}.tmp \
        -e 's:@-PREFIX-@:${prefix}:g' \
        -e 's:@-PKGLIBDIR-@:${pkglibdir}:g' \
        -e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:g' \
        -e 's:@-PKGDOCDIR-@:${pkgdocdir}:g' \
        -e 's:@-PKGXMLDIR-@:${pkgxmldir}:g' \
        -e 's:@-PKGLOGDIR-@:${pkglogdir}:g' \
        -e 's:@-SHIRELOGDIR-@:${shirelogdir}:g' \
        -e 's:@-PKGRUNDIR-@:${pkgrundir}:g'
	cmp -s ${FILE} ${FILE}.tmp || mv ${FILE}.tmp ${FILE}
	rm -f ${FILE}.tmp

apache.config: ${srcdir}/apache.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

apache2.config: ${srcdir}/apache2.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

apache22.config: ${srcdir}/apache22.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-redhat: ${srcdir}/shibd-redhat.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-suse: ${srcdir}/shibd-suse.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-debian: ${srcdir}/shibd-debian.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-osx.plist: ${srcdir}/shibd-osx.plist.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd.logger: ${srcdir}/shibd.logger.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

native.logger: ${srcdir}/native.logger.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

all-data-local: $(BUILTCONFIGFILES)

install-data-local:	all-data-local
	$(mkinstalldirs) $(DESTDIR)$(pkglogdir)
	$(mkinstalldirs) $(DESTDIR)$(pkgdocdir)
	$(mkinstalldirs) $(DESTDIR)$(shirelogdir)
	$(mkinstalldirs) $(DESTDIR)$(pkgrundir)
	$(mkinstalldirs) $(DESTDIR)$(pkgxmldir)
	$(mkinstalldirs) $(DESTDIR)$(pkgsysconfdir)
	for f in $(BUILTCONFIGFILES); do \
		if test ! -f $(DESTDIR)${pkgsysconfdir}/$$f; then \
			$(INSTALL_DATA) $$f $(DESTDIR)${pkgsysconfdir}; \
		fi; \
		$(INSTALL_DATA) $$f $(DESTDIR)${pkgsysconfdir}/$$f.dist; \
        done
	for f in $(CONFIGFILES); do \
		if test ! -f $(DESTDIR)${pkgsysconfdir}/$$f; then \
			$(INSTALL_DATA) $(srcdir)/$$f $(DESTDIR)${pkgsysconfdir}; \
		fi; \
		$(INSTALL_DATA) $(srcdir)/$$f $(DESTDIR)${pkgsysconfdir}/$$f.dist; \
        done

install-data-hook:
	chmod +x $(DESTDIR)$(pkgsysconfdir)/keygen.sh
	chmod +x $(DESTDIR)$(pkgsysconfdir)/metagen.sh
	if test -z "$(NOKEYGEN)"; then \
		cd $(DESTDIR)$(pkgsysconfdir); \
		sh ./keygen.sh -b ; \
	fi

CLEANFILES = \
	apache.config \
	apache2.config \
	apache22.config \
	shibd-redhat \
	shibd-suse \
	shibd-debian \
	shibd-osx.plist \
	shibd.logger \
	native.logger

EXTRA_DIST = \
	native.logger.in \
	shibd.logger.in \
	apache.config.in \
	apache2.config.in \
	apache22.config.in \
	shibd-redhat.in \
	shibd-suse.in \
	shibd-debian.in \
	shibd-osx.plist.in \
	keygen.bat \
	keygen.sh \
	metagen.sh \
	upgrade.xsl \
	xsltproc.js \
	$(CONFIGFILES)
