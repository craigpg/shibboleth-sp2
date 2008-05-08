dnl @synopsis AC_CXX_NAMESPACES
dnl
dnl If the compiler can prevent names clashes using namespaces, define
dnl HAVE_NAMESPACES.
dnl
dnl @author Luc Maisonobe
dnl
AC_DEFUN([AC_CXX_NAMESPACES],
[AC_CACHE_CHECK(whether the compiler implements namespaces,
ac_cv_cxx_namespaces,
[AC_LANG_SAVE
 AC_LANG_CPLUSPLUS
 AC_TRY_COMPILE([namespace Outer { namespace Inner { int i = 0; }}],
                [using namespace Outer::Inner; return i;],
 ac_cv_cxx_namespaces=yes, ac_cv_cxx_namespaces=no)
 AC_LANG_RESTORE
])
if test "$ac_cv_cxx_namespaces" = yes; then
  AC_DEFINE(HAVE_NAMESPACES,1,[define if the compiler implements namespaces])
fi
])


dnl
dnl @author Luc Maisonobe
dnl
AC_DEFUN([AC_CXX_REQUIRE_STL],
[AC_CACHE_CHECK(whether the compiler supports Standard Template Library,
ac_cv_cxx_have_stl,
[AC_REQUIRE([AC_CXX_NAMESPACES])
 AC_LANG_SAVE
 AC_LANG_CPLUSPLUS
 AC_TRY_COMPILE([#include <list>
#include <deque>
#ifdef HAVE_NAMESPACES
using namespace std;
#endif],[list<int> x; x.push_back(5);
list<int>::iterator iter = x.begin(); if (iter != x.end()) ++iter; return 0;],
 ac_cv_cxx_have_stl=yes, ac_cv_cxx_have_stl=no)
 AC_LANG_RESTORE
])
if test "x_$ac_cv_cxx_have_stl" != x_yes; then
  AC_MSG_ERROR([C++ Standard Template Libary unsupported])
fi
])

dnl@synopsys YAD_CHECK_INCLUDE_LIB(INCLUDE, LIBRARY, CODE
dnl              [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND
dnl              [, OTHER-LIBRARIES]]])
dnl 
dnl same as the AC_CHECK_LIB except of the following:
dnl      - You sholud specify include part of test.
dnl      - You can test any code for linking, not just function calls.
dnl
dnl@author Alexandr Yanovets <yad@gradsoft.kiev.ua>
dnl
AC_DEFUN(YAD_CHECK_INCLUDE_LIB,
[AC_MSG_CHECKING([for $3 in -l$2])
dnl Use a cache variable name containing both the library and function name,
dnl because the test really is for library $2 defining function $3, not
dnl just for library $2.  Separate tests with the same $2 and different $3s
dnl may have different results.
ac_lib_var=`echo $2['_']include | sed 'y%./+-%__p_%'`
AC_CACHE_VAL(ac_cv_lib_$ac_lib_var,
[yad_check_lib_save_LIBS="$LIBS"
LIBS="-l$2 $6 $LIBS"
AC_TRY_LINK(dnl
            [$1],
	    [$3],
	    eval "ac_cv_lib_$ac_lib_var=yes",
	    eval "ac_cv_lib_$ac_lib_var=no")
LIBS="$yad_check_lib_save_LIBS"
])dnl
if eval "test \"`echo '$ac_cv_lib_'$ac_lib_var`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$4], ,
[changequote(, )dnl
  ac_tr_lib=HAVE_LIB`echo $2 | sed -e 's/[^a-zA-Z0-9_]/_/g' \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'`
changequote([, ])dnl
  AC_DEFINE_UNQUOTED($ac_tr_lib)
  LIBS="-l$2 $LIBS"
], [$4])
else
  AC_MSG_RESULT(no)
ifelse([$5], , , [$5
])dnl
fi
])

