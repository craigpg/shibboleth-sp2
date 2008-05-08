AUTOMAKE_OPTIONS = foreign

if BUILD_FASTCGI

fastcgidir = $(libdir)/@PACKAGE@

fastcgi_PROGRAMS = shibauthorizer shibresponder

shibauthorizer_SOURCES = shibauthorizer.cpp
shibauthorizer_CXXFLAGS = -I$(FASTCGI_INCLUDE)
shibauthorizer_LDFLAGS = $(FASTCGI_LDFLAGS) $(FASTCGI_LIBS)
shibauthorizer_LDADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la

shibresponder_SOURCES = shibresponder.cpp
shibresponder_CXXFLAGS = -I$(FASTCGI_INCLUDE)
shibresponder_LDFLAGS = $(FASTCGI_LDFLAGS) $(FASTCGI_LIBS)
shibresponder_LDADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la

endif

EXTRA_DIST = \
    shibauthorizer.cpp \
    shibauthorizer.vcproj \
    shibauthorizer.rc \
    shibresponder.cpp \
    shibresponder.vcproj \
    shibresponder.rc \
    resource.h
