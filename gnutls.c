/*
   +-------------------------------------------------------------------------+
   | GnuTLS Extension for PHP Version 5                                      |
   +-------------------------------------------------------------------------+
   | Copyright (c) 2013 NetAware Inc                                         |
   +-------------------------------------------------------------------------+
   / This program is free software; you can redistribute it and/or modify    /
   / it under the terms of the GNU General Public License as published by    /
   / the Free Software Foundation; either version 2 of the License, or       /
   / (at your option) any later version.                                     /
   /                                                                         /
   / This program is distributed in the hope that it will be useful,         /
   / but WITHOUT ANY WARRANTY; without even the implied warranty of          /
   / MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the            /
   / GNU General Public License for more details.                            /
   /                                                                         /
   / You should have received a copy of the GNU General Public License along /
   / with this program; if not, write to the Free Software Foundation, Inc., /
   / 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.             /
   +-------------------------------------------------------------------------+
   / gnutls@netawareinc.com                                                                        /
   +-------------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_gnutls.h"

/* PHP Includes */
#include "ext/standard/file.h"
#include "ext/standard/info.h"
#include "ext/standard/php_fopen_wrappers.h"
#include "ext/standard/md5.h"
#include "ext/standard/base64.h"

/* GnuTLS includes */
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* Common */
#include <time.h>

/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO(arginfo_gnutls_void, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_init, 0)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_deinit, 0)
    ZEND_ARG_INFO(0, session)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_session_generic, 0)
    ZEND_ARG_INFO(0, session)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_handshake, 0)
    ZEND_ARG_INFO(0, session)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_socket, 0)
    ZEND_ARG_INFO(0, socket)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_priority_set_direct, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(0, priority)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_certificate_set_x509_trust_file, 0)
    ZEND_ARG_INFO(0, cred)
    ZEND_ARG_INFO(0, cafile)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_certificate_set_x509_trust_mem, 0)
    ZEND_ARG_INFO(0, cred)
    ZEND_ARG_INFO(0, ca)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_certificate_verify_peers2, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(1, status)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_certificate_verify_peers3, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(0, hostname)
    ZEND_ARG_INFO(1, status)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_bye, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(0, how)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_cipher_get_key_size, 0)
    ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_compression_get_name, 0)
    ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_credentials_set, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, cred)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_certificate_set_verify_flags, 0)
    ZEND_ARG_INFO(0, cred)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_check_version, 0)
    ZEND_ARG_INFO(0, req_version)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_transport_set_ptr, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(0, socket)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_record_recv, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(1, data)
    ZEND_ARG_INFO(0, len)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_certificate_get_peers, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(1, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_crt_export, 0)
    ZEND_ARG_INFO(0, cert)
    ZEND_ARG_INFO(0, format)
    ZEND_ARG_INFO(1, output)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_crt_get_dn, 0)
    ZEND_ARG_INFO(0, cert)
    ZEND_ARG_INFO(1, output)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_record_send, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, len)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_handshake_set_timeout, 0)
    ZEND_ARG_INFO(0, session)
    ZEND_ARG_INFO(0, ms)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_error_is_fatal, 0)
    ZEND_ARG_INFO(0, error)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_strerror, 0)
    ZEND_ARG_INFO(0, error)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_crt_generic, 0)
    ZEND_ARG_INFO(0, cert)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_crt_import, 0)
    ZEND_ARG_INFO(0, cert)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, format)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_crt_check_hostname, 0)
    ZEND_ARG_INFO(0, cert)
    ZEND_ARG_INFO(0, hostname)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_crt_print, 0)
    ZEND_ARG_INFO(0, cert)
    ZEND_ARG_INFO(0, format)
    ZEND_ARG_INFO(1, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_crt_get_serial, 0)
    ZEND_ARG_INFO(0, cert)
    ZEND_ARG_INFO(1, serial)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_crt_get_signature, 0)
    ZEND_ARG_INFO(0, cert)
    ZEND_ARG_INFO(1, signature)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_crt_get_signature_algorithm, 0)
    ZEND_ARG_INFO(0, cert)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_gnutls_x509_dn_deinit, 0)
    ZEND_ARG_INFO(0, dn)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ gnutls_functions[]
 */
const zend_function_entry gnutls_functions[] = {
/* PHP API */
	PHP_FE(gnutls_socket, arginfo_gnutls_socket)

/* Core TLS API */
	PHP_FE(gnutls_init, arginfo_gnutls_init)
	PHP_FE(gnutls_deinit, arginfo_gnutls_deinit)
	PHP_FE(gnutls_check_version, arginfo_gnutls_check_version)
	PHP_FE(gnutls_transport_set_ptr, arginfo_gnutls_transport_set_ptr)
	PHP_FE(gnutls_priority_set_direct, arginfo_gnutls_priority_set_direct)
	PHP_FE(gnutls_credentials_set, arginfo_gnutls_credentials_set)
	PHP_FE(gnutls_handshake_set_timeout, arginfo_gnutls_handshake_set_timeout)
	PHP_FE(gnutls_record_recv, arginfo_gnutls_record_recv)
	PHP_FE(gnutls_record_send, arginfo_gnutls_record_send)
	PHP_FE(gnutls_error_is_fatal, arginfo_gnutls_error_is_fatal)
	PHP_FE(gnutls_strerror, arginfo_gnutls_strerror)
	PHP_FE(gnutls_strerror_name, arginfo_gnutls_strerror)
	PHP_FE(gnutls_certificate_get_peers, arginfo_gnutls_certificate_get_peers)
	PHP_FE(gnutls_certificate_allocate_credentials, arginfo_gnutls_void)
	PHP_FE(gnutls_certificate_type_get, arginfo_gnutls_session_generic)
	PHP_FE(gnutls_certificate_set_verify_flags, arginfo_gnutls_certificate_set_verify_flags)
	PHP_FE(gnutls_certificate_set_x509_trust_file, arginfo_gnutls_certificate_set_x509_trust_file)
	PHP_FE(gnutls_certificate_set_x509_trust_mem, arginfo_gnutls_certificate_set_x509_trust_mem)
	PHP_FE(gnutls_certificate_verify_peers2, arginfo_gnutls_certificate_verify_peers2)
	PHP_FE(gnutls_certificate_verify_peers3, arginfo_gnutls_certificate_verify_peers3)
	PHP_FE(gnutls_cipher_get, arginfo_gnutls_session_generic)
	PHP_FE(gnutls_cipher_get_key_size, arginfo_gnutls_cipher_get_key_size)
	PHP_FE(gnutls_compression_get, arginfo_gnutls_session_generic)
	PHP_FE(gnutls_compression_get_name, arginfo_gnutls_compression_get_name)

/* X.509 Certificate API */
	PHP_FE(gnutls_x509_crt_init, arginfo_gnutls_void)
	PHP_FE(gnutls_x509_crt_deinit, arginfo_gnutls_x509_crt_generic)
	PHP_FE(gnutls_x509_crt_get_activation_time, arginfo_gnutls_x509_crt_generic)
	PHP_FE(gnutls_x509_crt_get_expiration_time, arginfo_gnutls_x509_crt_generic)
	PHP_FE(gnutls_x509_crt_get_version, arginfo_gnutls_x509_crt_generic)
	PHP_FE(gnutls_x509_crt_export, arginfo_gnutls_x509_crt_export)
	PHP_FE(gnutls_x509_crt_import, arginfo_gnutls_x509_crt_import)
	PHP_FE(gnutls_x509_crt_check_hostname, arginfo_gnutls_x509_crt_check_hostname)
	PHP_FE(gnutls_x509_crt_print, arginfo_gnutls_x509_crt_print)
	PHP_FE(gnutls_x509_crt_get_dn, arginfo_gnutls_x509_crt_get_dn)
	PHP_FE(gnutls_x509_crt_get_serial, arginfo_gnutls_x509_crt_get_serial)
	PHP_FE(gnutls_x509_crt_get_signature, arginfo_gnutls_x509_crt_get_signature)
	PHP_FE(gnutls_x509_crt_get_signature_algorithm, arginfo_gnutls_x509_crt_get_signature_algorithm)
	PHP_FE(gnutls_x509_dn_init, arginfo_gnutls_void)
	PHP_FE(gnutls_x509_dn_deinit, arginfo_gnutls_x509_dn_deinit)

/* TLS Handshake */
	PHP_FE(gnutls_handshake, arginfo_gnutls_handshake)
	PHP_FE(gnutls_bye, arginfo_gnutls_bye)

	PHP_FE_END
};
/* }}} */

/* {{{ gnutls_module_entry
 */
zend_module_entry gnutls_module_entry = {
	STANDARD_MODULE_HEADER,
	"gnutls",
	gnutls_functions,
	PHP_MINIT(gnutls),
	PHP_MSHUTDOWN(gnutls),
	NULL,
	NULL,
	PHP_MINFO(gnutls),
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_GNUTLS
ZEND_GET_MODULE(gnutls)
#endif

static gnutls_certificate_credentials_t xcred;

static int le_sess;
static int le_cred;
static int le_cert;
static int le_datum;
static int le_dn;

/* {{{ resource destructors */
static void php_list_free(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	assert(rsrc->ptr != NULL);
}
/* }}} */

/* {{{ gnutls safe_mode & open_basedir checks */
inline static int php_gnutls_safe_mode_chk(char *filename TSRMLS_DC)
{
	if (PG(safe_mode) && (!php_checkuid(filename, NULL, CHECKUID_CHECK_FILE_AND_DIR))) {
		return -1;
	}
	if (php_check_open_basedir(filename TSRMLS_CC)) {
		return -1;
	}
	
	return 0;
}
/* }}} */

static gnutls_session_t php_gnutls_session_resource(INTERNAL_FUNCTION_PARAMETERS)
{
	gnutls_session_t session;
	zval *zsession;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zsession) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

	return session;
}

static gnutls_x509_crt_t php_gnutls_cert_resource(INTERNAL_FUNCTION_PARAMETERS)
{
	gnutls_x509_crt_t cert;
	zval *zcert;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zcert) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cert, gnutls_x509_crt_t, &zcert, -1, "Certificate", le_cert);

	return cert;
}

static gnutls_x509_dn_t php_gnutls_dn_resource(INTERNAL_FUNCTION_PARAMETERS)
{
	gnutls_x509_dn_t dn;
	zval *zdn;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zdn) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(dn, gnutls_x509_dn_t, &zdn, -1, "DN", le_dn);

	return dn;
}

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(gnutls)
{
	le_sess = zend_register_list_destructors_ex(php_list_free, NULL, "GnuTLS session", module_number);
	le_cert = zend_register_list_destructors_ex(php_list_free, NULL, "GnuTLS X.509 certificate", module_number);
	le_cred = zend_register_list_destructors_ex(php_list_free, NULL, "GnuTLS credential", module_number);
	le_datum = zend_register_list_destructors_ex(php_list_free, NULL, "GnuTLS datum", module_number);
	le_dn = zend_register_list_destructors_ex(php_list_free, NULL, "GnuTLS X.509 DN", module_number);

	gnutls_global_init();

	/* GnuTSL Error Codes */
	REGISTER_LONG_CONSTANT("GNUTLS_E_SUCCESS", GNUTLS_E_SUCCESS, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_E_INTERNAL_ERROR", GNUTLS_E_INTERNAL_ERROR, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_E_ASN1_TAG_ERROR", GNUTLS_E_ASN1_TAG_ERROR, CONST_CS|CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("GNUTLS_X509_FMT_DER", GNUTLS_X509_FMT_DER, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_X509_FMT_PEM", GNUTLS_X509_FMT_PEM, CONST_CS|CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("GNUTLS_CRT_PRINT_FULL", GNUTLS_CRT_PRINT_FULL, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_CRT_PRINT_ONELINE", GNUTLS_CRT_PRINT_ONELINE, CONST_CS|CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("GNUTLS_CLIENT", GNUTLS_CLIENT, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_SERVER", GNUTLS_SERVER, CONST_CS|CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("GNUTLS_CRD_ANON", GNUTLS_CRD_ANON, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_CRD_CERTIFICATE", GNUTLS_CRD_CERTIFICATE, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_CRD_SRP", GNUTLS_CRD_SRP, CONST_CS|CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("GNUTLS_SHUT_RDWR", GNUTLS_SHUT_RDWR, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_SHUT_WR", GNUTLS_SHUT_WR, CONST_CS|CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("GNUTLS_COMP_UNKNOWN", GNUTLS_COMP_UNKNOWN, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_COMP_NULL", GNUTLS_COMP_NULL, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_COMP_DEFLATE", GNUTLS_COMP_DEFLATE, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_COMP_ZLIB", GNUTLS_COMP_ZLIB, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_COMP_LZO", GNUTLS_COMP_LZO, CONST_CS|CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("GNUTLS_CERT_INVALID", GNUTLS_CERT_INVALID, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_CERT_REVOKED", GNUTLS_CERT_REVOKED, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_CERT_SIGNER_NOT_FOUND", GNUTLS_CERT_SIGNER_NOT_FOUND, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_CERT_SIGNER_NOT_CA", GNUTLS_CERT_SIGNER_NOT_CA, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_CERT_INSECURE_ALGORITHM", GNUTLS_CERT_INSECURE_ALGORITHM, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_CERT_NOT_ACTIVATED", GNUTLS_CERT_NOT_ACTIVATED, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_CERT_EXPIRED", GNUTLS_CERT_EXPIRED, CONST_CS|CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("GNUTLS_VERIFY_DISABLE_CA_SIGN", GNUTLS_VERIFY_DISABLE_CA_SIGN, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT", GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_VERIFY_DO_NOT_ALLOW_SAME", GNUTLS_VERIFY_DO_NOT_ALLOW_SAME, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT", GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2", GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5", GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_VERIFY_DISABLE_TIME_CHECKS", GNUTLS_VERIFY_DISABLE_TIME_CHECKS, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS", GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUTLS_VERIFY_DO_NOT_ALLOW_X509_V1_CA_CRT", GNUTLS_VERIFY_DO_NOT_ALLOW_X509_V1_CA_CRT, CONST_CS|CONST_PERSISTENT);
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(gnutls)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "GnuTLS support", "enabled");
	php_info_print_table_row(2, "GnuTLS Library Version", gnutls_check_version("1.0.0"));
	php_info_print_table_row(2, "GnuTLS Header Version", GNUTLS_VERSION);
	php_info_print_table_end();
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(gnutls)
{
	gnutls_global_deinit();

	return SUCCESS;
}
/* }}} */

/* {{{ proto resource gnutls_init(int flags)
	Initializes a session and returns a session resource */
PHP_FUNCTION(gnutls_init)
{
	gnutls_session_t session;
	unsigned long flags;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &flags) == FAILURE) {
		return;
	}

	if (gnutls_init(&session, (unsigned int) flags) != GNUTLS_E_SUCCESS) {
		RETURN_FALSE;
	}

	ZEND_REGISTER_RESOURCE(return_value, session, le_sess);
}
/* }}} */

/* {{{ proto int gnutls_handshake(resource session)
*/
PHP_FUNCTION(gnutls_handshake)
{
	int rval = GNUTLS_E_INVALID_SESSION;

	gnutls_session_t session;

	session = php_gnutls_session_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (session) {
		rval = gnutls_handshake(session);
	}

	RETURN_LONG(rval);
}
/* }}} */

/* {{{ proto int gntuls_bye(resource session, int how)
*/
PHP_FUNCTION(gnutls_bye)
{
	gnutls_session_t session;
	zval *zsession;
	long how;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &zsession, &how) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

	RETURN_LONG(gnutls_bye(session, how));
}
/* }}} */

/* {{{ proto int gnutls_deinit(resource session)
*/
PHP_FUNCTION(gnutls_deinit)
{
	gnutls_session_t session;

	session = php_gnutls_session_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (session) {
		gnutls_deinit(session);
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto string gnutls_check_version(string req_version)
*/
PHP_FUNCTION(gnutls_check_version)
{
	char * req_version;
	int req_version_len;
	const char * version;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &req_version, &req_version_len) == FAILURE) {
		return;
	}

	if ((version = gnutls_check_version((const char *) req_version)) != NULL) {
		RETURN_STRING(version, 1);
	}

	RETURN_NULL();
}
/* }}} */

/* {{{ proto string gnutls_sterror(int error)
*/
PHP_FUNCTION(gnutls_strerror)
{
	long error;
	const char * errstr;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &error) == FAILURE) {
		return;
	}

	if ((errstr = gnutls_strerror(error)) != NULL) {
		RETURN_STRING(errstr, 1);
	}

	RETURN_NULL();
}
/* }}} */

/* {{{ proto string gnutls_strerror_name(int error)
*/
PHP_FUNCTION(gnutls_strerror_name)
{
	long error;
	const char * errstr;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &error) == FAILURE) {
		return;
	}

	if ((errstr = gnutls_strerror_name(error)) != NULL) {
		RETURN_STRING(errstr, 1);
	}

	RETURN_NULL();
}

/* }}} */

/* {{{ proto int gnutls_socket(resource socket)
*/
PHP_FUNCTION(gnutls_socket)
{
	php_socket *sock;	/* Sockets extension socket resource */
	zval *zsock;
	int type;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zsock) == FAILURE) {
		return;
	}

	zend_list_find(Z_RESVAL_P(zsock), &type);

	ZEND_FETCH_RESOURCE(sock, php_socket *, &zsock, -1, php_sockets_le_socket_name, type);
	
	RETURN_LONG(sock->bsd_socket);
}
/* }}} */

/* {{{ proto int gnutls_transport_set_ptr(resource session, resource socket)
*/
PHP_FUNCTION(gnutls_transport_set_ptr)
{
	gnutls_session_t session;
	php_socket *sock;	/* Sockets extension socket resource */
	zval *zsock;
	zval *zsession;
	int type;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rr", &zsession, &zsock) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

	zend_list_find(Z_RESVAL_P(zsock), &type);

	ZEND_FETCH_RESOURCE(sock, php_socket *, &zsock, -1, php_sockets_le_socket_name, type);
	
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) sock->bsd_socket);

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto int gnutls_priority_set_direct(resource session, string priorities)
*/
PHP_FUNCTION(gnutls_priority_set_direct)
{
	gnutls_session_t session;
	zval *zsession;
	char *priorities;
	int priorities_len;
	const char *err_pos;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zsession, &priorities, &priorities_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

	RETURN_LONG(gnutls_priority_set_direct(session, priorities, &err_pos));
}
/* }}} */

/* {{{ proto int gnutls_certificate_set_verify_flags(resource credentials, int flags)
*/
PHP_FUNCTION(gnutls_certificate_set_verify_flags)
{
	gnutls_certificate_credentials_t cred;
	zval *zcred;
	unsigned long flags;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &zcred, &flags) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cred, gnutls_certificate_credentials_t, &zcred, -1, "Credentials", le_cred);

	gnutls_certificate_set_verify_flags(cred, flags);
}	
/* }}} */

/* {{{ proto int gnutls_certificate_verify_peers2(resource session, int status)
*/
PHP_FUNCTION(gnutls_certificate_verify_peers2)
{
	gnutls_session_t session;
	zval *zsession;
	unsigned int status;
	zval *zstatus;
	int retval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz", &zsession, &zstatus) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

	if ((retval = gnutls_certificate_verify_peers2(session, &status)) == GNUTLS_E_SUCCESS) {
		Z_LVAL_P(zstatus) = status;
		Z_TYPE_P(zstatus) = IS_LONG;
	}
	
	RETURN_LONG(retval);
}
/* }}} */

/* {{{ int proto gnutls_certificate_verify_peers3(resource session, string hostname, int status)
*/
PHP_FUNCTION(gnutls_certificate_verify_peers3)
{
	gnutls_session_t session;
	zval *zsession;
	char *hostname;
	int hostname_len;
	unsigned int status;
	zval *zstatus;
	int retval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsz", &zsession, &hostname, &hostname_len, &zstatus) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

	if ((retval = gnutls_certificate_verify_peers3(session, hostname, &status)) == GNUTLS_E_SUCCESS) {
		Z_LVAL_P(zstatus) = status;
		Z_TYPE_P(zstatus) = IS_LONG;
	}
	
	RETURN_LONG(retval);
}
/* }}} */

/* {{{ proto gnutls_credentials_set(resource session, int type, resource credentials)
*/
PHP_FUNCTION(gnutls_credentials_set)
{
	gnutls_session_t session;
	zval *zsession;
	zval *zcred;
	gnutls_certificate_credentials_t crd;
	long type;
	int retval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rlr", &zsession, &type, &zcred) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

	switch (type) {
		case GNUTLS_CRD_CERTIFICATE:
			ZEND_FETCH_RESOURCE(crd, gnutls_certificate_credentials_t, &zcred, -1, "Credentials", le_cred);
			retval = gnutls_credentials_set(session, type, crd);
			break;

		default:
			RETURN_LONG(-1);
			break;
	}


	RETURN_LONG(retval);
}
/* }}} */

/* {{{ proto int gnutls_certificate_type_get(resource session)
*/
PHP_FUNCTION(gnutls_certificate_type_get)
{
	gnutls_session_t session;

	session = php_gnutls_session_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	RETURN_LONG(gnutls_certificate_type_get(session));
}
/* }}} */

/* {{{ proto int gnutls_compression_get(resource session)
*/
PHP_FUNCTION(gnutls_compression_get)
{
	gnutls_session_t session;

	session = php_gnutls_session_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	RETURN_LONG(gnutls_compression_get(session));
}
/* }}} */

/* {{{ proto int gnutls_ciper_get(resource session)
*/
PHP_FUNCTION(gnutls_cipher_get)
{
	gnutls_session_t session;

	session = php_gnutls_session_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	RETURN_LONG(gnutls_cipher_get(session));
}
/* }}} */

/* {{{ proto int gnutls_cipher_get_key_size(int algorithm)
*/
PHP_FUNCTION(gnutls_cipher_get_key_size)
{
	long algorithm;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &algorithm) == FAILURE) {
		return;
	}

	RETURN_LONG(gnutls_cipher_get_key_size(algorithm));
}
/* }}} */

/* {{{ proto int gnutls_compression_get_name(int algorithm)
*/
PHP_FUNCTION(gnutls_compression_get_name)
{
	long algorithm;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &algorithm) == FAILURE) {
		return;
	}

	RETURN_STRING(gnutls_compression_get_name(algorithm), 1);
}
/* }}} */

/* {{{ proto int gnutls_handshake_set_timeout(resource session, int ms)
*/
PHP_FUNCTION(gnutls_handshake_set_timeout)
{
	gnutls_session_t session;
	zval *zsession;
	unsigned long ms;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &zsession, &ms) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

	gnutls_handshake_set_timeout(session, ms);

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto int gnutls_record_send(resource session, string data, int data_size)
*/
PHP_FUNCTION(gnutls_record_send)
{
	gnutls_session_t session;
	zval *zsession;
        char *send_buf;
	long send_buf_len;
	long len;
        int retval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsl", &zsession, &send_buf, &send_buf_len, &len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

        retval = gnutls_record_send(session, send_buf, len);

        RETURN_LONG(retval);
}
/* }}} */

/* {{{ proto int gnutls_error_is_fatal(int error)
*/
PHP_FUNCTION(gnutls_error_is_fatal)
{
	long error;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &error) == FAILURE) {
		return;
	}

        RETURN_LONG(gnutls_error_is_fatal(error));
}
/* }}} */

/* {{{ int proto gnutls_x509_crt_get_signature_algorithm(resource certificate)
*/
PHP_FUNCTION(gnutls_x509_crt_get_signature_algorithm)
{
	gnutls_x509_crt_t cert;

	cert = php_gnutls_cert_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	RETURN_LONG(gnutls_x509_crt_get_signature_algorithm(cert));
}
/* }}} */

/* {{{ proto int gnutls_record_recv(resource session, string data, int data_len)
*/
PHP_FUNCTION(gnutls_record_recv)
{
	gnutls_session_t session;
	zval *zsession;
	zval *zbuf;
        char *recv_buf;
	long len;
        int retval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rzl", &zsession, &zbuf, &len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

        /* overflow check */
        if ((len + 1) < 2) {
                RETURN_FALSE;
        }

        recv_buf = emalloc(len + 1);
        memset(recv_buf, 0, len + 1);

        if ((retval = gnutls_record_recv(session, recv_buf, len)) < 1) {
                efree(recv_buf);

                zval_dtor(zbuf);
                Z_TYPE_P(zbuf) = IS_NULL;
        } else {
                recv_buf[retval] = '\0';

                /* Rebuild buffer zval */
                zval_dtor(zbuf);

                Z_STRVAL_P(zbuf) = recv_buf;
                Z_STRLEN_P(zbuf) = retval;
                Z_TYPE_P(zbuf) = IS_STRING;
        }

        RETURN_LONG(retval);
}
/* }}} */

/* {{{ proto resource gnutls_x509_crt_init()
*/
PHP_FUNCTION(gnutls_x509_crt_init)
{
	gnutls_x509_crt_t cert;

	if (gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS) {
		RETURN_FALSE;
	}

	ZEND_REGISTER_RESOURCE(return_value, cert, le_cert);
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_deinit(resource certificate)
*/
PHP_FUNCTION(gnutls_x509_crt_deinit)
{
	gnutls_x509_crt_t cert;

	cert = php_gnutls_cert_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (cert) {
		gnutls_x509_crt_deinit(cert);
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto resource gnutls_x509_dn_init()
*/
PHP_FUNCTION(gnutls_x509_dn_init)
{
	gnutls_x509_dn_t dn;

	if (gnutls_x509_dn_init(&dn) != GNUTLS_E_SUCCESS) {
		RETURN_FALSE;
	}

	ZEND_REGISTER_RESOURCE(return_value, dn, le_dn);
}
/* }}} */

/* {{{ proto int gnutls_x509_dn_deinit(resource dn)
*/
PHP_FUNCTION(gnutls_x509_dn_deinit)
{
	gnutls_x509_dn_t dn;

	dn = php_gnutls_dn_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	if (dn) {
		gnutls_x509_dn_deinit(dn);

		efree(dn);
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_get_activation_time(resource certificate)
*/
PHP_FUNCTION(gnutls_x509_crt_get_activation_time)
{
	gnutls_x509_crt_t cert;

	cert = php_gnutls_cert_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	RETURN_LONG(gnutls_x509_crt_get_activation_time(cert));
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_get_expiration_time(resource certificate)
*/
PHP_FUNCTION(gnutls_x509_crt_get_expiration_time)
{
	gnutls_x509_crt_t cert;

	cert = php_gnutls_cert_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	RETURN_LONG(gnutls_x509_crt_get_expiration_time(cert));
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_get_version(resource certificate)
*/
PHP_FUNCTION(gnutls_x509_crt_get_version)
{
	gnutls_x509_crt_t cert;

	cert = php_gnutls_cert_resource(INTERNAL_FUNCTION_PARAM_PASSTHRU);

	RETURN_LONG(gnutls_x509_crt_get_version(cert));
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_import(resource certificate, string encoded, int format)
*/
PHP_FUNCTION(gnutls_x509_crt_import)
{
	gnutls_x509_crt_t cert;
	zval *zcert;
	char *encoded;
	long encoded_len;
	gnutls_datum_t data;
	gnutls_x509_crt_fmt_t format;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsl", &zcert, &encoded, &encoded_len, &format) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cert, gnutls_x509_crt_t, &zcert, -1, "Certificate", le_cert);

	data.data = encoded;
	data.size = encoded_len;

	RETURN_LONG(gnutls_x509_crt_import(cert, &data, format));
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_export(resource certificate, int format, string data)
*/
PHP_FUNCTION(gnutls_x509_crt_export)
{
	gnutls_x509_crt_t cert;
	zval *zcert;
	long format;
	zval *zbuf;
        size_t size = 16384;
	char *out;
        int retval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rlz", &zcert, &format, &zbuf) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cert, gnutls_x509_crt_t, &zcert, -1, "Certificate", le_cert);

        out = emalloc(size);

	if ((retval = gnutls_x509_crt_export(cert, format, out, &size)) != GNUTLS_E_SUCCESS) {
                zval_dtor(zbuf);
                Z_TYPE_P(zbuf) = IS_NULL;

		efree(out);

		RETURN_LONG(retval);
	}

	/* Rebuild buffer zval */
	zval_dtor(zbuf);

	Z_STRVAL_P(zbuf) = erealloc(out, size);
	Z_STRLEN_P(zbuf) = size;
	Z_TYPE_P(zbuf) = IS_STRING;

        RETURN_LONG(retval);
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_get_dn(resource certificate, string name)
*/
PHP_FUNCTION(gnutls_x509_crt_get_dn)
{
	gnutls_x509_crt_t cert;
	zval *zcert;
	zval *zbuf;
        size_t size = 1024;
	char *out;
        int retval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz", &zcert, &zbuf) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cert, gnutls_x509_crt_t, &zcert, -1, "Certificate", le_cert);

        out = emalloc(size);

	if ((retval = gnutls_x509_crt_get_dn(cert, out, &size)) != GNUTLS_E_SUCCESS) {
                zval_dtor(zbuf);
                Z_TYPE_P(zbuf) = IS_NULL;

		efree(out);

		RETURN_LONG(retval);
	}

	/* Rebuild buffer zval */
	zval_dtor(zbuf);

	Z_STRVAL_P(zbuf) = erealloc(out, size);
	Z_STRLEN_P(zbuf) = size;
	Z_TYPE_P(zbuf) = IS_STRING;

        RETURN_LONG(retval);
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_check_hostname(resource certificate, string hostname)
*/
PHP_FUNCTION(gnutls_x509_crt_check_hostname)
{
	gnutls_x509_crt_t cert;
	zval *zcert;
	char *hostname;
	long hostname_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zcert, &hostname, &hostname_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cert, gnutls_x509_crt_t, &zcert, -1, "Certificate", le_cert);

	RETURN_LONG(gnutls_x509_crt_check_hostname(cert, hostname));
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_get_signature(resource certificate, string signature)
*/
PHP_FUNCTION(gnutls_x509_crt_get_signature)
{
	gnutls_x509_crt_t cert;
	zval *zcert;
	zval *zbuf;
	char *sig;
	int size;
        int retval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz", &zcert, &zbuf) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cert, gnutls_x509_crt_t, &zcert, -1, "Certificate", le_cert);

	size = 1024;
	sig = emalloc(size);

	if ((retval = gnutls_x509_crt_get_signature(cert, sig, &size)) != GNUTLS_E_SUCCESS) {
                zval_dtor(zbuf);
                Z_TYPE_P(zbuf) = IS_NULL;

		efree(sig);

		RETURN_LONG(retval);
	}

	/* Rebuild buffer zval */
	zval_dtor(zbuf);

	Z_STRVAL_P(zbuf) = erealloc(sig, size);
	Z_STRLEN_P(zbuf) = size;
	Z_TYPE_P(zbuf) = IS_STRING;

        RETURN_LONG(retval);
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_print(resource certificate, int format, string output)
*/
PHP_FUNCTION(gnutls_x509_crt_print)
{
	gnutls_x509_crt_t cert;
	zval *zcert;
	long format;
	zval *zbuf;
        gnutls_datum_t dat;
	char *out;
        int retval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rlz", &zcert, &format, &zbuf) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cert, gnutls_x509_crt_t, &zcert, -1, "Certificate", le_cert);

	if ((retval = gnutls_x509_crt_print(cert, format, &dat)) != GNUTLS_E_SUCCESS) {
                zval_dtor(zbuf);
                Z_TYPE_P(zbuf) = IS_NULL;

		RETURN_LONG(retval);
	}

        out = emalloc(dat.size);
        memcpy(out, dat.data, dat.size);

	gnutls_free(dat.data);

	/* Rebuild buffer zval */
	zval_dtor(zbuf);

	Z_STRVAL_P(zbuf) = out;
	Z_STRLEN_P(zbuf) = dat.size;
	Z_TYPE_P(zbuf) = IS_STRING;

        RETURN_LONG(retval);
}
/* }}} */

/* {{{ proto int gnutls_x509_crt_get_serial(resource certificate, int serial)
*/
PHP_FUNCTION(gnutls_x509_crt_get_serial)
{
	gnutls_x509_crt_t cert;
	zval *zcert;
	zval *zbuf;
        int retval;
	unsigned char *result;
	unsigned long serial = 0L;
	int i;
	int size = sizeof(unsigned long);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz", &zcert, &zbuf) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cert, gnutls_x509_crt_t, &zcert, -1, "Certificate", le_cert);

        result = emalloc(size);
        memset(result, 0, size);

	if ((retval = gnutls_x509_crt_get_serial(cert, result, &size)) != GNUTLS_E_SUCCESS) {
		efree(result);

                zval_dtor(zbuf);
                Z_TYPE_P(zbuf) = IS_NULL;

		RETURN_LONG(retval);
	}

	for (i = 0; i < size; i++) {
		serial |= result[i];
		serial <<= 8;
	}

	efree(result);

	/* Rebuild buffer zval */
	zval_dtor(zbuf);

	Z_LVAL_P(zbuf) = serial;
	Z_TYPE_P(zbuf) = IS_LONG;

        RETURN_LONG(retval);
}
/* }}} */

/* {{{ proto resource gnutls_certificate_allocate_credentials()
*/
PHP_FUNCTION(gnutls_certificate_allocate_credentials)
{
	gnutls_certificate_credentials_t cred;

	cred = (gnutls_certificate_credentials_t) emalloc(sizeof(gnutls_certificate_credentials_t));

	if (gnutls_certificate_allocate_credentials(&cred) != GNUTLS_E_SUCCESS) {
		efree(cred);

		RETURN_FALSE;
	}

	ZEND_REGISTER_RESOURCE(return_value, cred, le_cred);
}
/* }}} */

/* {{{ proto array gnutls_certificate_get_peers(resource session, int list_size)
*/
PHP_FUNCTION(gnutls_certificate_get_peers)
{
	gnutls_session_t session;
	zval *zsession;
	zval *zsize;
	const gnutls_datum_t *dat;
	unsigned int list_size = 0;
	int i;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz", &zsession, &zsize) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, gnutls_session_t, &zsession, -1, "Session", le_sess);

	array_init(return_value);

	if ((dat = gnutls_certificate_get_peers(session, &list_size)) != NULL) {
		for (i = 0; i < list_size; i++) {
			add_next_index_stringl(return_value, dat[i].data, dat[i].size, 1);
		}

		Z_LVAL_P(zsize) = list_size;
		Z_TYPE_P(zsize) = IS_LONG;
	}
}
/* }}} */

/* {{{ proto int gnutls_certificate_set_x509_trust_file(resource credentials, string cafile, int type)
*/
PHP_FUNCTION(gnutls_certificate_set_x509_trust_file)
{
	gnutls_certificate_credentials_t cred;
	zval *zcred;
	char *cafile;
	int cafile_len;
        long type;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsl", &zcred, &cafile, &cafile_len, &type) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(cred, gnutls_certificate_credentials_t, &zcred, -1, "Credentials", le_cred);

	RETURN_LONG(gnutls_certificate_set_x509_trust_file(cred, cafile, type));
}
/* }}} */

/* {{{ proto int gnutls_certificate_set_x509_trust_mem()
*/
PHP_FUNCTION(gnutls_certificate_set_x509_trust_mem)
{
}

/* }}} */
