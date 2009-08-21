AC_PREREQ([2.50])
AC_INIT([shibboleth], [2.2.1], [shibboleth-users@internet2.edu], [shibboleth])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([shibboleth],[2.2.1])

sinclude(doxygen.m4)
sinclude(acx_pthread.m4)

# Docygen features
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(shibboleth, doxygen.cfg, doc/api)
DX_INCLUDE=

AC_ARG_ENABLE(debug,
    AC_HELP_STRING(--enable-debug, [Have GCC compile with symbols (Default = no)
]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    GCC_CFLAGS="$CFLAGS -g -D_DEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -g -D_DEBUG"
else
    GCC_CFLAGS="$CFLAGS -O2 -DNDEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -O2 -DNDEBUG"
fi

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])
AC_CANONICAL_HOST

if test "$GCC" = "yes" ; then
#    AC_HAVE_GCC_VERSION(4,0,0,0,
#        [
#        AC_DEFINE(GCC_HASCLASSVISIBILITY,1,
#            [Define to enable class visibility control in gcc.])
#        GCC_CFLAGS="$GCC_CFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
#        GCC_CXXFLAGS="$GCC_CXXFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
#        ])
    CFLAGS="-Wall $GCC_CFLAGS"
    CXXFLAGS="-Wall $GCC_CXXFLAGS"
else
# Fix for Sun Workshop compiler in debug mode, may be Sun case #6360993
	case "${host_cpu}-${host_os}" in
	        *solaris*)
			if test "$CXX" = "CC" ; then
				CXXFLAGS="$CXXFLAGS -Qoption ccfe -stabs=no%dfltlit+no%dflthlp"
			fi
			;;
	        *osf*)
			CXXFLAGS="$CXXFLAGS -D_POSIX_PII_SOCKET"
			;;
	esac
fi

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_LANG(C)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_STRFTIME
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([strchr strdup strstr timegm gmtime_r strtok_r strcasecmp])

# checks for pthreads
ACX_PTHREAD([enable_threads="pthread"],[enable_threads="no"])
if test $enable_threads != "pthread"; then
    AC_MSG_ERROR([unable to find pthreads, currently this is required])
else
    AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.])
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
    CXXFLAGS="$PTHREAD_CFLAGS $CXXFLAGS"
fi

# OpenSSL settings
AC_ARG_WITH(openssl,
    AC_HELP_STRING([--with-openssl=PATH], [where openssl is installed]),
    [if test x_$with_openssl != x_/usr; then
        SSLFLAGS="-I${with_openssl}/include"
    fi])

if test "x$SSLFLAGS" = "x" ; then
    AC_PATH_PROG(PKG_CONFIG, pkg-config)
    if test "x$PKG_CONFIG" != x && test "x$PKG_CONFIG" != "xno" ; then
        if pkg-config openssl ; then
            SSLFLAGS="`$PKG_CONFIG --cflags openssl`"
        else
            AC_MSG_ERROR([OpenSSL not supported by pkg-config, try --with-openssl instead])
        fi
    fi
fi

AC_MSG_CHECKING(for OpenSSL cflags)
AC_MSG_RESULT($SSLFLAGS)
CPPFLAGS="$SSLFLAGS $CPPFLAGS"

AC_CHECK_HEADER([openssl/x509.h],,
                AC_MSG_ERROR([unable to find openssl header files]))

AC_LANG(C++)

# C++ requirements
AC_CXX_REQUIRE_STL
AC_CXX_NAMESPACES

# Thank you Solaris, really.
AC_MSG_CHECKING(for ctime_r)
 if test -z "$ac_cv_ctime_args"; then
     AC_TRY_COMPILE(
     [#include <time.h>],
     [
         time_t clock;
         char buf[26];
         ctime_r(&clock, buf);
     ], ac_cv_ctime_args=2)

     AC_TRY_COMPILE(
     [#include <time.h>],
     [
         time_t clock;
         char buf[26];
         ctime_r(&clock, buf, 26);
     ], ac_cv_ctime_args=3)
 fi
 if test -z "$ac_cv_ctime_args"; then
     AC_MSG_RESULT(no)
 else
     if test "$ac_cv_ctime_args" = 2; then
         AC_DEFINE(HAVE_CTIME_R_2,1,[Define if ctime_r is present with 2 parameters.])
     elif test "$ac_cv_ctime_args" = 3; then
         AC_DEFINE(HAVE_CTIME_R_3,1,[Define if ctime_r is present with 3 parameters.])
     fi
     AC_MSG_RESULT([yes, and it takes $ac_cv_ctime_args arguments])
 fi 

# log4shib settings (favor this version over the log4cpp code)
AC_PATH_PROG(LOG4SHIB_CONFIG,log4shib-config)
AC_ARG_WITH(log4shib,
    AC_HELP_STRING([--with-log4shib=PATH], [where log4shib-config is installed]),
    [
    LOG4SHIB_CONFIG="${with_log4shib}"
    if ! test -f "${LOG4SHIB_CONFIG}" ; then
    	LOG4SHIB_CONFIG="${with_log4shib}/bin/log4shib-config"
    fi
    ])
if test -f "${LOG4SHIB_CONFIG}"; then
    LDFLAGS="`${LOG4SHIB_CONFIG} --libs` $LDFLAGS"
    CPPFLAGS="`${LOG4SHIB_CONFIG} --cflags` $CPPFLAGS"
	AC_CHECK_HEADER([log4shib/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4shib header files]))
	AC_TRY_LINK(
		[#include <log4shib/Category.hh>
#include <log4shib/CategoryStream.hh>],
		[log4shib::Category::getInstance("foo").errorStream() << log4shib::eol],
		[AC_DEFINE(SHIBSP_LOG4SHIB,1,[Define if log4shib library is used.])],
		[AC_MSG_ERROR([unable to link with log4shib])])
else
    AC_MSG_WARN([log4shib-config not found, may need to use --with-log4shib option])
    AC_MSG_WARN([will look for original log4cpp library])
    
	# log4cpp settings
	AC_PATH_PROG(LOG4CPP_CONFIG,log4cpp-config)
	AC_ARG_WITH(log4cpp,
	    AC_HELP_STRING([--with-log4cpp=PATH], [where log4cpp-config is installed]),
	    [
	    LOG4CPP_CONFIG="${with_log4cpp}"
	    if ! test -f "${LOG4CPP_CONFIG}" ; then
	    	LOG4CPP_CONFIG="${with_log4cpp}/bin/log4cpp-config"
	    fi
	    ])
	if test -f "${LOG4CPP_CONFIG}"; then
		AC_MSG_WARN([will try to use log4cpp, note that most non-Internet2 supplied versions are not thread-safe])
	    LDFLAGS="`${LOG4CPP_CONFIG} --libs` $LDFLAGS"
	    CPPFLAGS="`${LOG4CPP_CONFIG} --cflags` $CPPFLAGS"
		AC_CHECK_HEADER([log4cpp/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4cpp header files]))
		AC_TRY_LINK(
			[#include <log4cpp/Category.hh>
#include <log4cpp/CategoryStream.hh>],
			[log4cpp::Category::getInstance("foo").errorStream() << log4cpp::eol],
			[AC_DEFINE(SHIBSP_LOG4CPP,1,[Define if log4cpp library is used.])],
			[AC_MSG_ERROR([unable to link with log4cpp, need version 1.0 or later])])
	else
	    AC_MSG_ERROR([log4cpp-config not found, may need to use --with-log4cpp option])
	fi
fi

# Xerces settings
AC_ARG_WITH(xerces, 
            AC_HELP_STRING([--with-xerces=PATH], [where xerces-c is installed]),
            [if test x_$with_xerces != x_/usr; then
                LDFLAGS="-L${with_xerces}/lib $LDFLAGS"
                CPPFLAGS="-I${with_xerces}/include $CPPFLAGS"
            fi])
LIBS="-lxerces-c $LIBS"
AC_CHECK_HEADER([xercesc/dom/DOM.hpp],,
                AC_MSG_ERROR([unable to find xerces header files]))
AC_MSG_CHECKING([Xerces version])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([#include <xercesc/util/XercesVersion.hpp>],
[#if  _XERCES_VERSION != 20600
int i = 0;
#else
#error cannot use version 2.6.0
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([Xerces-C v2.6.0 has bugs that inhibit use with signed XML, please use a newer version])])
AC_TRY_LINK(
        [#include <xercesc/util/PlatformUtils.hpp>],
        [xercesc::XMLPlatformUtils::Initialize()],
        [AC_DEFINE(HAVE_LIBXERCESC,1,[Define if Xerces-C library was found])],
        [AC_MSG_ERROR([unable to link with Xerces])])

AC_MSG_CHECKING([whether Xerces XMLString::release(XMLByte**) exists])
AC_TRY_COMPILE([#include <xercesc/util/XMLString.hpp>],
    [using namespace XERCES_CPP_NAMESPACE;
      XMLByte* buf=NULL;
      XMLString::release(&buf);
    ],
    [AC_MSG_RESULT([yes])]
    [AC_DEFINE([SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE], [1], [Define to 1 if Xerces XMLString includes XMLByte release.])],
    [AC_MSG_RESULT([no])])

AC_MSG_CHECKING([whether Xerces DOMNodeFilter API returns a short])
AC_TRY_COMPILE([#include <xercesc/dom/DOM.hpp>],
    [using namespace XERCES_CPP_NAMESPACE;
      class Blocker : public DOMNodeFilter {
      public:
        short acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
      };
      static Blocker g_Blocker;
    ],
    [AC_MSG_RESULT([yes])]
    [AC_DEFINE([SHIBSP_XERCESC_SHORT_ACCEPTNODE], [1], [Define to 1 if Xerces DOMNodeFilter API returns a short.])],
    [AC_MSG_RESULT([no])])

#XML-Tooling settings
AC_ARG_WITH(xmltooling,
            AC_HELP_STRING([--with-xmltooling=PATH], [where xmltooling-c is installed]),
            [if test x_$with_xmltooling != x_/usr; then
                LDFLAGS="-L${with_xmltooling}/lib $LDFLAGS"
                CPPFLAGS="-I${with_xmltooling}/include $CPPFLAGS"
            fi])
LITE_LIBS="-lxmltooling-lite"
XMLSEC_LIBS="-lxmltooling"
AC_CHECK_HEADER([xmltooling/base.h],,
                AC_MSG_ERROR([unable to find xmltooling header files]))

# Establish location of xmltooling catalog.
XMLTOOLINGXMLDIR=""
if test "x$with_xmltooling" = "x" ; then
   with_xmltooling="/usr"
fi
if test -f $with_xmltooling/share/xml/xmltooling/catalog.xml ; then
    XMLTOOLINGXMLDIR="$with_xmltooling"
elif test -f $with_xerces/share/xml/xmltooling/catalog.xml ; then
    XMLTOOLINGXMLDIR="$with_xerces"
elif test -f $with_log4shib/share/xml/xmltooling/catalog.xml ; then
    XMLTOOLINGXMLDIR="$with_log4shib"
fi
if test "x$XMLTOOLINGXMLDIR" = "x" ; then
    AC_MSG_ERROR([xmltooling XML catalog not found, may need to use --with-xmltooling option])
fi
XMLTOOLINGXMLDIR="$XMLTOOLINGXMLDIR/share/xml/xmltooling"
AC_SUBST(XMLTOOLINGXMLDIR)

# XML-Security settings
AC_ARG_WITH(xmlsec,
            AC_HELP_STRING([--with-xmlsec=PATH], [where xmlsec is installed]),,
            [with_xmlsec=/usr])

if test x_$with_xmlsec != x_/usr; then
    LDFLAGS="-L${with_xmlsec}/lib $LDFLAGS"
    CPPFLAGS="-I${with_xmlsec}/include $CPPFLAGS"
fi        
XMLSEC_LIBS="-lxml-security-c $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([xsec/utils/XSECPlatformUtils.hpp],,AC_MSG_ERROR([unable to find XML-Security header files]))
AC_MSG_CHECKING([XML-Security version])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([#include <xsec/utils/XSECPlatformUtils.hpp>],
    [#if XSEC_VERSION_MAJOR > 1 || (XSEC_VERSION_MAJOR == 1 && XSEC_VERSION_MEDIUM > 3)
int i = 0;
#else
#error need version 1.4.0 or later
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([XML-Security version 1.4.0 or greater is required.])])
AC_TRY_LINK(
        [#include <xsec/utils/XSECPlatformUtils.hpp>],
        [XSECPlatformUtils::Initialise()],,
        [AC_MSG_ERROR([unable to link with XML-Security])])

# restore master libs
LIBS="$save_LIBS"

# OpenSAML settings
AC_ARG_WITH(saml,
    AC_HELP_STRING([--with-saml=PATH], [where saml is installed]),
    [if test x_$with_saml != x_/usr; then
        LDFLAGS="-L${with_saml}/lib $LDFLAGS"
        CPPFLAGS="-I${with_saml}/include $CPPFLAGS"
    fi])
XMLSEC_LIBS="-lsaml $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([saml/saml2/metadata/Metadata.h],,
                AC_MSG_ERROR([unable to find OpenSAML header files]))
AC_TRY_LINK(
	[#include <saml/SAMLConfig.h>
#include <saml/version.h>],
	[#if _OPENSAML_VERSION >= 20200
opensaml::SAMLConfig::getConfig();
#else
#error Need OpenSAML version 2.2 or higher
#endif],
        [AC_DEFINE(HAVE_SAML,1,[Define if saml library was found])],
        [AC_MSG_ERROR([unable to link with OpenSAML, or version was too old])])

# restore master libs
LIBS="$save_LIBS"

# Establish location of opensaml catalogs.
OPENSAMLXMLDIR=""
if test "x$with_saml" = "x" ; then
    with_saml="/usr"
fi
if test -f $with_saml/share/xml/opensaml/saml20-catalog.xml ; then
    OPENSAMLXMLDIR="$with_saml"
elif test -f $with_xmltooling/share/xml/opensaml/saml20-catalog.xml ; then
    OPENSAMLXMLDIR="$with_xmltooling"
elif test -f $with_xerces/share/xml/opensaml/saml20-catalog.xml ; then
    OPENSAMLXMLDIR="$with_xerces"
elif test -f $with_log4shib/share/xml/opensaml/saml20-catalog.xml ; then
    OPENSAMLXMLDIR="$with_log4shib"
fi
if test "x$OPENSAMLXMLDIR" = "x" ; then
    AC_MSG_ERROR([opensaml XML catalogs not found, may need to use --with-saml option])
fi
OPENSAMLXMLDIR="$OPENSAMLXMLDIR/share/xml/opensaml"
AC_SUBST(OPENSAMLXMLDIR)

AC_SUBST(LITE_LIBS)
AC_SUBST(XMLSEC_LIBS)

AC_CONFIG_FILES([shibboleth.spec pkginfo Portfile])

# output the underlying makefiles
WANT_SUBDIRS="doc schemas configs shibsp shibd util"
AC_CONFIG_FILES([Makefile doc/Makefile schemas/Makefile \
	configs/Makefile shibsp/Makefile shibd/Makefile \
	util/Makefile selinux/Makefile])

## ADFS?
AC_CONFIG_FILES([adfs/Makefile])
AC_ARG_ENABLE([adfs],
	AC_HELP_STRING([--disable-adfs], [don't build the ADFS module]),
	[adfs_enabled=$enableval], [adfs_enabled=yes])
if test "x$adfs_enabled" = "x" ; then
   adfs_enabled=yes
fi
AC_MSG_CHECKING(whether to build the ADFS module)
if test "$adfs_enabled" = "no" ; then
   AC_MSG_RESULT(no)
else
   AC_MSG_RESULT(yes)
   WANT_SUBDIRS="$WANT_SUBDIRS adfs"
fi


#
# Build NSAPI module?
#
AC_MSG_CHECKING(for NSAPI module option)
AC_ARG_WITH(nsapi,
	AC_HELP_STRING([--with-nsapi=DIR], [Build NSAPI module for Netscape/iPlanet/SunONE]),
	[WANT_NSAPI=$withval],[WANT_NSAPI=no])
AC_MSG_RESULT($WANT_NSAPI)

if test "$WANT_NSAPI" != "no"; then
  if test ! -d $WANT_NSAPI/bin ; then
    AC_MSG_ERROR(Please specify the path to the root of your Netscape/iPlanet/SunONE server using --with-nsapi=DIR)
  fi
  AC_MSG_CHECKING(for NSAPI include files)
  if test -d $WANT_NSAPI/include ; then
    NSAPI_INCLUDE=$WANT_NSAPI/include
    AC_MSG_RESULT(Netscape-Enterprise 3.x style)
    AC_CHECK_HEADERS([$NSAPI_INCLUDE/nsapi.h],,,[#define XP_UNIX])
    NSAPI_INCLUDE="$NSAPI_INC_DIR -I$NSAPI_INCLUDE"
  fi
  if test -d $WANT_NSAPI/plugins/include ; then
    test -n "$NSAPI_INCLUDE" && NSAPI_INC_DIR="-I$NSAPI_INCLUDE"
    NSAPI_INCLUDE="$WANT_NSAPI/plugins/include"
    AC_MSG_RESULT(iPlanet 4.x / SunONE 6.x style)
    AC_CHECK_HEADERS([$NSAPI_INCLUDE/nsapi.h],,,[#define XP_UNIX])
    NSAPI_INCLUDE="$NSAPI_INC_DIR -I$NSAPI_INCLUDE"
  fi
  if test "$NSAPI_INCLUDE" = ""; then
    AC_MSG_ERROR(Please check you have nsapi.h in either $WANT_NSAPI/include or $WANT_NSAPI/plugins/include)
  fi
fi

AC_SUBST(NSAPI_INCLUDE)

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([nsapi_shib/Makefile])
AM_CONDITIONAL(BUILD_NSAPI,test ! "$WANT_NSAPI" = "no")

# add the NSAPI module to the list of wanted subdirs..
if test ! "$WANT_NSAPI" = "no" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS nsapi_shib"
fi


#
# Build FastCGI support?
#
AC_MSG_CHECKING(for FastCGI support)
AC_ARG_WITH(fastcgi,
    AC_HELP_STRING([--with-fastcgi=DIR], [Build FastCGI support]),
    [WANT_FASTCGI=$withval],[WANT_FASTCGI=no])
AC_MSG_RESULT($WANT_FASTCGI)

if test "$WANT_FASTCGI" != "no"; then
    if test "$WANT_FASTCGI" != "yes"; then
        if test x_$WANT_FASTCGI != x_/usr; then
            FASTCGI_INCLUDE="-I$WANT_FASTCGI/include"
            FASTCGI_LDFLAGS="-L$WANT_FASTCGI/lib"
        fi
    fi
    AC_CHECK_HEADER([fcgio.h],,
        AC_MSG_ERROR([unable to find FastCGI header files]))
    FASTCGI_LIBS="-lfcgi -lfcgi++"
fi

AC_SUBST(FASTCGI_INCLUDE)
AC_SUBST(FASTCGI_LDFLAGS)
AC_SUBST(FASTCGI_LIBS)

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([fastcgi/Makefile])
AM_CONDITIONAL(BUILD_FASTCGI,test ! "$WANT_FASTCGI" = "no")

if test ! "$WANT_FASTCGI" = "no" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS fastcgi"
fi

#
# Build Memcached support?
#
AC_MSG_CHECKING(for Memcached support)
AC_ARG_WITH(memcached,
    AC_HELP_STRING([--with-memcached=DIR], [Build Memcached support]),
    [WANT_MEMCACHED=$withval],[WANT_MEMCACHED=no])
AC_MSG_RESULT($WANT_MEMCACHED)

if test "$WANT_MEMCACHED" != "no"; then
    if test "$WANT_MEMCACHED" != "yes"; then
        if test x_$WANT_MEMCACHED != x_/usr; then
            MEMCACHED_INCLUDE="-I$WANT_MEMCACHED/include"
            MEMCACHED_LDFLAGS="-L$WANT_MEMCACHED/lib"
        fi
    fi
    AC_CHECK_HEADER([libmemcached/memcached.h],,
        AC_MSG_ERROR([unable to find Memcached header files]))
    MEMCACHED_LIBS="-lmemcached"
fi

AC_SUBST(MEMCACHED_INCLUDE)
AC_SUBST(MEMCACHED_LDFLAGS)
AC_SUBST(MEMCACHED_LIBS)

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([memcache-store/Makefile])
AM_CONDITIONAL(BUILD_MEMCACHED,test ! "$WANT_MEMCACHED" = "no")

if test ! "$WANT_MEMCACHED" = "no" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS memcache-store"
fi


#
# If no --enable-apache-xx specified 
# find a default and fake the specific parameters
#

# simple macro to peek at an enable or a with
AC_DEFUN([Peek],
if test "[${[$1]_][$2]+set}" = set; then
  peekval="${[$1]_[$2]}"
  $3
fi; dnl
)

AC_MSG_CHECKING(if default apache needed)
need_default=yes
Peek(enable,apache_13,need_default=no)
Peek(enable,apache_20,need_default=no)
Peek(enable,apache_22,need_default=no)
AC_MSG_RESULT($need_default)

if test "$need_default" = "yes"; then
  # find an apxs, then the httpd
  xs=
  Peek(with,apxs,xs="$peekval")
  Peek(with,apxs2,xs="$peekval")
  Peek(with,apxs22,xs="$peekval")
  if test "x$xs" = "x"; then
     AC_PATH_PROGS(xs, apxs2 apxs,
        AC_MSG_ERROR(No apxs, no apache found.  Try --with-apxs),
        [/usr/local/apache2/bin:/usr/local/apache/bin:/usr/sbin:$PATH])
  fi
  # ask the daemon for the version and set parameters
  AC_MSG_CHECKING(default apache version)
  httpd="`$xs -q SBINDIR`/`$xs -q TARGET`"
  if test "x$httpd" != "x" && test -f $httpd ; then
     v=`$httpd -v|$SED -n -e 's/.*Apache\/\.*//p'`
     case $v in
       1.3*)   [enable_apache_13]=yes
               [with_apxs]=$xs
               AC_MSG_RESULT(1.3)
               ;;
       2.0*)   [enable_apache_20]=yes
               [with_apxs2]=$xs
               AC_MSG_RESULT(2.0)
               ;;
       2.2*)   [enable_apache_22]=yes
               [with_apxs22]=$xs
               AC_MSG_RESULT(2.2)
               ;;
       *)      AC_MSG_ERROR(unusable apache versions: $v. Try setting --with-apxs)
     esac
  else 
     AC_MSG_RESULT(cannot determine version.  Try setting --with-apxs)
  fi
fi

# Apache 1.3 (mod_shib_13)
#   --enable-apache-13
#   --with-apxs      (DSO build, the normal way, uses apxs to derive build flags)

AC_ARG_ENABLE(apache-13,
	AC_HELP_STRING([--enable-apache-13], [enable the Apache 1.3 module]),
	[ if test "x$enableval" = "x" ; then
              WANT_APACHE_13=yes
	  else
	      WANT_APACHE_13="$enableval"
	  fi
	],[ WANT_APACHE_13=no ])
AC_MSG_CHECKING(whether to build Apache 1.3 module)
if test "$WANT_APACHE_13" != yes && test "$WANT_APACHE_13" != no ; then
   WANT_APACHE_13=yes
fi
AC_MSG_RESULT($WANT_APACHE_13)

if test "$WANT_APACHE_13" = "yes" ; then
    AC_ARG_WITH(apxs, 
        AC_HELP_STRING([--with-apxs=FILE], [Specifies where to find the Apache 1.3 apxs script.]),
        [
        AC_MSG_CHECKING(for user-specified apxs name/location)
        if test "$withval" != "no" ; then
          if test "$withval" != "yes"; then
            APXS=$withval
            AC_MSG_RESULT("$withval")
          fi
        fi
        ],
        [
        AC_PATH_PROG(APXS, apxs, no)
        if test "$APXS" = "no" ; then
          for i in /usr/sbin /usr/local/apache/bin ; do
            if test "$APXS" = "no" && test -f "$i/apxs"; then
              APXS="$i/apxs"
            fi
          done
        fi
        ])

    AC_MSG_CHECKING([to see if apxs was located])
    if test ! -f "$APXS" ; then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to locate apxs script. An Apache development package may be missing from your server, or you may need to use the --with-apxs option.])
    fi
    AC_MSG_RESULT($APXS)
    AC_SUBST(APXS)

    # extract settings we need from APXS -q
    APXS_CC="`$APXS -q CC`"
    APXS_CFLAGS="`$APXS -q CFLAGS` `$APXS -q CFLAGS_SHLIB`"
    APXS_INCLUDE="`$APXS -q INCLUDEDIR`"
fi

AC_SUBST(APXS_CFLAGS)
AC_SUBST(APXS_INCLUDE)


# Apache 2.0 (mod_shib_20)
#   --enable-apache-20
#   --with-apxs2      (DSO build, the normal way, uses apxs to derive build flags)
#	--with-apr        (DSO build, APR development package installed separately)

AC_ARG_ENABLE(apache-20,
	AC_HELP_STRING([--enable-apache-20], [enable the Apache 2.0 module]),
	[ if test "x$enableval" = "x" ; then
              WANT_APACHE_20=yes
	  else
	      WANT_APACHE_20="$enableval"
	  fi
	],[ WANT_APACHE_20=no ])
AC_MSG_CHECKING(whether to build Apache 2.0 module)
if test "$WANT_APACHE_20" != yes && test "$WANT_APACHE_20" != no ; then
   WANT_APACHE_20=yes
fi
AC_MSG_RESULT($WANT_APACHE_20)

if test "$WANT_APACHE_20" = "yes" ; then
    AC_ARG_WITH(apxs2, 
        AC_HELP_STRING([--with-apxs2=FILE], [Specifies where to find the Apache 2.0 apxs script.]),
        [
        AC_MSG_CHECKING(for user-specified Apache2 apxs name/location)
        if test "$withval" != "no" ; then
          if test "$withval" != "yes"; then
            APXS2=$withval
            AC_MSG_RESULT("$withval")
          fi
        fi
        ],
        [
        AC_PATH_PROG(APXS2, apxs2, no)
        if test "$APXS2" = "no" ; then
            AC_PATH_PROG(APXS2, apxs, no)
        fi
        if test "$APXS2" = "no" ; then
          for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin ; do
            if test "$APXS2" = "no" && test -f "$i/apxs2" ; then
              APXS2="$i/apxs2"
            fi
          done
          if test "$APXS2" = "no" ; then
            for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin ; do
              if test "$APXS2" = "no" && test -f "$i/apxs" ; then
                APXS2="$i/apxs"
              fi
            done
          fi
        fi
        ])

    AC_MSG_CHECKING([to see if Apache2 apxs was located])
    if test ! -f "$APXS2" ; then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to locate Apache2 apxs script. An Apache development package may be missing from your server, or you may need to use the --with-apxs2 option.])
    fi
    AC_MSG_RESULT($APXS2)
    AC_SUBST(APXS2)

    # APR settings
    AC_ARG_WITH(apr, 
        AC_HELP_STRING([--with-apr=PATH], [where apr-config is installed]),
        [
        AC_MSG_CHECKING(for user-specified apr-config name/location)
        if test "$withval" != "no" ; then
            if test "$withval" != "yes"; then
                APR_CONFIG=$withval
                AC_MSG_RESULT("$withval")
            fi
        fi
        ],
        [
        AC_PATH_PROG(APR_CONFIG, apr-config,,[`$APXS2 -q SBINDIR`]:[$PATH])
        ])
	if test -f "${APR_CONFIG}"; then
        APR_CFLAGS="`${APR_CONFIG} --cflags` `${APR_CONFIG} --cppflags` `${APR_CONFIG} --includes`"
    else
        AC_MSG_ERROR([Unable to locate apr-config, may need --with-apr option.])
    fi

    # extract settings we need from APXS2 -q
    APXS2_CC="`$APXS2 -q CC`"
    APXS2_CFLAGS="`$APXS2 -q CPPFLAGS` `$APXS2 -q CFLAGS` $APR_CFLAGS"
    APXS2_INCLUDE="`$APXS2 -q INCLUDEDIR`"
fi

AC_SUBST(APXS2_CFLAGS)
AC_SUBST(APXS2_INCLUDE)


# Apache 2.2 (mod_shib_22)
#   --enable-apache-22
#   --with-apxs22     (DSO build, the normal way, uses apxs to derive build flags)
#	--with-apr1       (DSO build, APR development package installed separately)

AC_ARG_ENABLE(apache-22,
	AC_HELP_STRING([--enable-apache-22], [enable the Apache 2.2 module]),
	[ if test "x$enableval" = "x" ; then
              WANT_APACHE_22=yes
	  else
	      WANT_APACHE_22="$enableval"
	  fi
	],[ WANT_APACHE_22=no ])
AC_MSG_CHECKING(whether to build Apache 2.2 module)
if test "$WANT_APACHE_22" != yes && test "$WANT_APACHE_22" != no ; then
   WANT_APACHE_22=yes
fi
AC_MSG_RESULT($WANT_APACHE_22)

if test "$WANT_APACHE_22" = "yes" ; then
    AC_ARG_WITH(apxs22, 
        AC_HELP_STRING([--with-apxs22=FILE], [Specifies where to find the Apache 2.2 apxs script.]),
        [
        AC_MSG_CHECKING(for user-specified Apache2.2 apxs name/location)
        if test "$withval" != "no" ; then
          if test "$withval" != "yes"; then
            APXS22=$withval
            AC_MSG_RESULT("$withval")
          fi
        fi
        ],
        [
        AC_PATH_PROG(APXS22, apxs2, no)
        if test "$APXS22" = "no" ; then
            AC_PATH_PROG(APXS22, apxs, no)
        fi
        if test "$APXS22" = "no" ; then
          for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin ; do
            if test "$APXS22" = "no" && test -f "$i/apxs2" ; then
              APXS22="$i/apxs2"
            fi
          done
          if test "$APXS22" = "no" ; then
            for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin ; do
              if test "$APXS22" = "no" && test -f "$i/apxs" ; then
                APXS22="$i/apxs"
              fi
            done
          fi
        fi
        ])

    AC_MSG_CHECKING([to see if Apache2.2 apxs was located])
    if test ! -f "$APXS22" ; then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to locate Apache2.2 apxs script. An Apache development package may be missing from your server, or you may need to use the --with-apxs22 option.])
    fi
    AC_MSG_RESULT($APXS22)
    AC_SUBST(APXS22)

    # APR1 settings
    AC_ARG_WITH(apr1, 
        AC_HELP_STRING([--with-apr1=PATH], [where apr-1-config is installed]),
        [
        AC_MSG_CHECKING(for user-specified apr-1-config name/location)
        if test "$withval" != "no" ; then
            if test "$withval" != "yes"; then
                APR1_CONFIG=$withval
                AC_MSG_RESULT("$withval")
            fi
        fi
        ],
        [
        AC_PATH_PROG(APR1_CONFIG, apr-1-config,,[`$APXS22 -q SBINDIR`]:[$PATH])
        ])
	if test -f "${APR1_CONFIG}"; then
        APR1_CFLAGS="`${APR1_CONFIG} --cflags` `${APR1_CONFIG} --cppflags` `${APR1_CONFIG} --includes`"
    else
        AC_MSG_ERROR([Unable to locate apr-1-config, may need --with-apr1 option.])
    fi

    # extract settings we need from APXS22 -q
    APXS22_CC="`$APXS22 -q CC`"
    APXS22_CFLAGS="`$APXS22 -q CPPFLAGS` `$APXS22 -q CFLAGS` $APR1_CFLAGS"
    APXS22_INCLUDE="`$APXS22 -q INCLUDEDIR`"
fi

AC_SUBST(APXS22_CFLAGS)
AC_SUBST(APXS22_INCLUDE)

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([apache/Makefile])
AM_CONDITIONAL(BUILD_AP13,test "$WANT_APACHE_13" = "yes")
AM_CONDITIONAL(BUILD_AP20,test "$WANT_APACHE_20" = "yes")
AM_CONDITIONAL(BUILD_AP22,test "$WANT_APACHE_22" = "yes")

# add the apache module to the list of wanted subdirs..
if test "$WANT_APACHE_13" = "yes" || test "$WANT_APACHE_20" = "yes" || test "$WANT_APACHE_22" = "yes" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS apache"
fi


#
# Implement the checks of the ODBC Storage Service
#
# 1) Assume the user wants ODBC; if it's not found then just continue without
# 2) If the user specifically requested odbc, look for it and ERROR if not found
# 3) If the user specifically requested no odbc, don't build it.
#

AC_CONFIG_FILES([odbc-store/Makefile])

# determine whether we should enable the odbc ccache
AC_ARG_ENABLE([odbc],
	AC_HELP_STRING([--disable-odbc], [disable the ODBC Storage Service]),
	[odbc_enabled=$enableval], [odbc_enabled=default])

if test "x$odbc_enabled" = "x" ; then
   odbc_enabled=yes
fi

# Are we trying to build ODBC?
AC_MSG_CHECKING(whether to build the ODBC storage service)
if test "$odbc_enabled" = "yes" ; then
   build_odbc=yes
   AC_MSG_RESULT(yes)
elif test "$odbc_enabled" = "default" ; then
   build_odbc=yes
   AC_MSG_RESULT([yes, if it can be found])
else
   build_odbc=no
   AC_MSG_RESULT(no)
fi

# If we're trying to build ODBC, try to find the odbc_config program.
if test "$build_odbc" = "yes" ; then
   odbc_dir=""
   AC_ARG_WITH(odbc,
	AC_HELP_STRING([--with-odbc=PATH], [directory where odbc is installed]),
	    [if test "$with_odbc" = no ; then
               AC_MSG_ERROR([Try running --disable-odbc instead.])
             elif test "$with_odbc" != yes ; then
               odbc_dir="$with_odbc/bin"
               if test "$with_odbc" != /usr ; then
                 ODBC_CFLAGS="-I$with_odbc/include"
                 ODBC_LIBS="-L$with_odbc/lib"
               fi
             fi ])

   AC_PATH_PROG(ODBC_CONFIG, odbc_config, no, $odbc_dir $PATH )
   if test "$ODBC_CONFIG" = no ; then
      AC_MSG_WARN([Cannot find odbc_config, will try to guess settings.])
      ODBC_LIBS="$ODBC_LIBS -lodbc"
   else
      ODBC_CFLAGS=`$ODBC_CONFIG --cflags`
      ODBC_LIBS=`$ODBC_CONFIG --libs`
   fi

   save_CPPFLAGS="$CPPFLAGS"
   CPPFLAGS="$CPPFLAGS $ODBC_CFLAGS"

   AC_CHECK_HEADER([sql.h], [have_sql_h=yes], [have_sql_h=no])
   if test "$have_sql_h" = no -a "$odbc_enabled" = "yes" ; then
     AC_MSG_ERROR(unable to find ODBC header files)
   fi

   if test "$have_sql_h" = yes ; then
      save_LIBS="$LIBS"
      LIBS="$LIBS $ODBC_LIBS"
      AC_MSG_CHECKING(if we can link againt ODBC)
      AC_TRY_LINK(
        [#include <sql.h>
         #include <sqlext.h>
         #include <stdio.h>],
        [SQLSetEnvAttr(SQL_NULL_HANDLE, SQL_ATTR_CONNECTION_POOLING, (void*)SQL_CP_ONE_PER_HENV, 0)],
        [have_odbc_libs=yes],
        [have_odbc_libs=no])
      LIBS="$save_LIBS"

      if test "$have_odbc_libs" = no ; then
         if test "$odbc_enabled" = "yes" ; then
            AC_MSG_ERROR([unable to link with ODBC Library])
         else
            AC_MSG_RESULT(no, skipping ODBC)
         fi
      fi
   fi

   CPPFLAGS="$save_CPPFLAGS"
fi

# if have_odbc_libs=yes then go ahead with building ODBC
if test "$have_odbc_libs" = yes ; then
   # this AC_MSG_RESULT is from above!
   AC_MSG_RESULT(yes)
   WANT_SUBDIRS="$WANT_SUBDIRS odbc-store"
   AC_SUBST(ODBC_CFLAGS)
   AC_SUBST(ODBC_LIBS)
fi


AC_SUBST(WANT_SUBDIRS)

if test -n "$APXS_CC" && test "$APXS_CC" != "$CC" ; then
  echo "=================================================================="
  echo "WARNING: You have chosen to compile Apache-1.3 modules with a different"
  echo "         compiler than the one used to compile Apache."
  echo ""
  echo "    Current compiler:      $CC"
  echo "   Apache's compiler:      $APXS_CC"
  echo ""
  echo "This could cause problems."
  echo "=================================================================="
fi

if test -n "$APXS2_CC" && test "$APXS2_CC" != "$CC" ; then
  echo "=================================================================="
  echo "WARNING: You have chosen to compile Apache-2.0 modules with a different"
  echo "         compiler than the one used to compile Apache."
  echo ""
  echo "    Current compiler:      $CC"
  echo "   Apache's compiler:      $APXS2_CC"
  echo ""
  echo "This could cause problems."
  echo "=================================================================="
fi

if test -n "$APXS22_CC" && test "$APXS22_CC" != "$CC" ; then
  echo "=================================================================="
  echo "WARNING: You have chosen to compile Apache-2.2 modules with a different"
  echo "         compiler than the one used to compile Apache."
  echo ""
  echo "    Current compiler:      $CC"
  echo "   Apache's compiler:      $APXS22_CC"
  echo ""
  echo "This could cause problems."
  echo "=================================================================="
fi

LIBTOOL="$LIBTOOL --silent"

AC_OUTPUT
