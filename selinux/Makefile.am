## $Id: Makefile.am 2308 2007-06-12 04:56:15Z cantor $ 

AUTOMAKE_OPTIONS = foreign

varrundir = $(localstatedir)/run
BUILDFILES = shibshar.fc
CLEANFILES = $(BUILDFILES)

sepolicy = targeted
selinuxdir = $(sysconfdir)/selinux/targeted/src/policy
fcfiledir = $(selinuxdir)/file_contexts/program
fcfile_DATA = shibshar.fc

tefiledir = $(selinuxdir)/domains/program
tefile_DATA = shibshar.te

shibshar.fc: ${srcdir}/shibshar.fc.in Makefile ${top_builddir}/config.status
	rm -f $@.tmp
	sed < ${srcdir}/$@.in > $@.tmp \
	    -e 's:@-SBINDIR-@:${sbindir}:' \
	    -e 's:@-VARRUNDIR-@:${varrundir}:'
	cmp -s $@ $@.tmp || mv $@.tmp $@
	rm -f $@.tmp

EXTRA_DIST = shibshar.fc.in shibshar.te
