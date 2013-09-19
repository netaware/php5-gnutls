dnl
dnl $Id: config.m4 $
dnl

PHP_ARG_WITH(gnutls, for GnuTLS support,
[  --with-gnutls[=DIR]    Include GnuTLS support (requires GnuTLS >= 2.12.14)])

if test "$PHP_GNUTLS" != "no"; then
  PHP_SUBST(GNUTLS_SHARED_LIBADD)

  PHP_CHECK_LIBRARY(gnutls, gnutls_init,
  [
    PHP_ADD_LIBRARY(gnutls, 1, GNUTLS_SHARED_LIBADD)
    AC_DEFINE(HAVE_GNUTLS_EXT,1,[ ])
  ],[
    AC_MSG_ERROR([gnutls lib not installed])
  ])

  PHP_NEW_EXTENSION(gnutls, gnutls.c, $ext_shared)
fi
