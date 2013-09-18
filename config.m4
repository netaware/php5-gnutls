dnl
dnl $Id: config.m4 $
dnl

PHP_ARG_WITH(gnutls, for GnuTLS support,
[  --with-gnutls[=DIR]    Include GnuTLS support (requires GnuTLS >= 0.9.6)])

if test "$PHP_GNUTLS" != "no"; then
  PHP_NEW_EXTENSION(gnutls, gnutls.c, $ext_shared)
  PHP_SUBST(GNUTLS_SHARED_LIBADD)

  AC_DEFINE(HAVE_GNUTLS_EXT,1,[ ])
fi
