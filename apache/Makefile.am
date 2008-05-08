AUTOMAKE_OPTIONS = foreign

if BUILD_AP13
modshib13dir = $(libdir)/@PACKAGE@
modshib13_LTLIBRARIES = mod_shib_13.la
mod_shib_13_la_SOURCES = mod_shib_13.cpp
mod_shib_13_la_CXXFLAGS = $(APXS_CFLAGS) -I$(APXS_INCLUDE)
mod_shib_13_la_LDFLAGS = $(LITE_LIBS) -module -avoid-version
mod_shib_13_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la

install-exec-hook:
	for la in $(modshib13_LTLIBRARIES) ; do rm -f $(DESTDIR)$(modshib13dir)/$$la ; done

endif

if BUILD_AP20
modshib20dir = $(libdir)/@PACKAGE@
modshib20_LTLIBRARIES = mod_shib_20.la
mod_shib_20_la_SOURCES = mod_shib_20.cpp
mod_shib_20_la_CXXFLAGS = $(APXS2_CFLAGS) -I$(APXS2_INCLUDE)
mod_shib_20_la_LDFLAGS = $(LITE_LIBS) -module -avoid-version
mod_shib_20_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la

install-exec-hook:
	for la in $(modshib20_LTLIBRARIES) ; do rm -f $(DESTDIR)$(modshib20dir)/$$la ; done

endif

if BUILD_AP22
modshib22dir = $(libdir)/@PACKAGE@
modshib22_LTLIBRARIES = mod_shib_22.la
mod_shib_22_la_SOURCES = mod_shib_22.cpp
mod_shib_22_la_CXXFLAGS = $(APXS22_CFLAGS) -I$(APXS22_INCLUDE)
mod_shib_22_la_LDFLAGS = $(LITE_LIBS) -module -avoid-version
mod_shib_22_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la

install-exec-hook:
	for la in $(modshib22_LTLIBRARIES) ; do rm -f $(DESTDIR)$(modshib22dir)/$$la ; done

endif

EXTRA_DIST = mod_apache.cpp mod_shib_13.cpp mod_shib_20.cpp mod_shib_22.cpp \
	mod_shib13.vcproj mod_shib20.vcproj mod_shib22.vcproj \
	resource.h mod_shib_13.rc mod_shib_20.rc mod_shib_22.rc
