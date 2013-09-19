--TEST--
GnuTLS Basic Functions
--SKIPIF--
<?php 
if (!extension_loaded("gnutls")) die("skip"); 
?>
--FILE--
<?php
echo gnutls_check_version(null) . "\n";

echo gnutls_error_is_fatal(GNUTLS_E_SUCCESS) . "\n";
echo gnutls_error_is_fatal(GNUTLS_E_INTERNAL_ERROR) . "\n";

echo gnutls_strerror(GNUTLS_E_SUCCESS) . "\n";
echo gnutls_strerror(GNUTLS_E_INTERNAL_ERROR) . "\n";

echo gnutls_strerror_name(GNUTLS_E_SUCCESS) . "\n";
echo gnutls_strerror_name(GNUTLS_E_INTERNAL_ERROR) . "\n";

echo "OK!\n";

?>
--EXPECTF--
%d.%d.%d
0
1
Success.
GnuTLS internal error.
GNUTLS_E_SUCCESS
GNUTLS_E_INTERNAL_ERROR
OK!
