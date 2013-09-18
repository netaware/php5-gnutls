/* $Id$ */

#ifndef PHP_GNUTLS_H
#define PHP_GNUTLS_H

#ifdef HAVE_GNUTLS_EXT
extern zend_module_entry gnutls_module_entry;
#define phpext_gnutls_ptr &gnutls_module_entry

PHP_MINIT_FUNCTION(gnutls);
PHP_MSHUTDOWN_FUNCTION(gnutls);
PHP_MINFO_FUNCTION(gnutls);

PHP_FUNCTION(gnutls_bye);
PHP_FUNCTION(gnutls_certificate_allocate_credentials);
PHP_FUNCTION(gnutls_certificate_get_peers);
PHP_FUNCTION(gnutls_certificate_set_verify_flags);
PHP_FUNCTION(gnutls_certificate_set_x509_trust_file);
PHP_FUNCTION(gnutls_certificate_set_x509_trust_mem);
PHP_FUNCTION(gnutls_certificate_type_get);
PHP_FUNCTION(gnutls_certificate_verify_peers2);
PHP_FUNCTION(gnutls_certificate_verify_peers3);
PHP_FUNCTION(gnutls_check_version);
PHP_FUNCTION(gnutls_cipher_get);
PHP_FUNCTION(gnutls_cipher_get_key_size);
PHP_FUNCTION(gnutls_compression_get);
PHP_FUNCTION(gnutls_compression_get_name);
PHP_FUNCTION(gnutls_credentials_set);
PHP_FUNCTION(gnutls_crt_deinit);
PHP_FUNCTION(gnutls_crt_init);
PHP_FUNCTION(gnutls_deinit);
PHP_FUNCTION(gnutls_error_is_fatal);
PHP_FUNCTION(gnutls_handshake);
PHP_FUNCTION(gnutls_handshake_set_timeout);
PHP_FUNCTION(gnutls_init);
PHP_FUNCTION(gnutls_priority_set_direct);
PHP_FUNCTION(gnutls_record_recv);
PHP_FUNCTION(gnutls_record_send);
PHP_FUNCTION(gnutls_socket);
PHP_FUNCTION(gnutls_strerror);
PHP_FUNCTION(gnutls_strerror_name);
PHP_FUNCTION(gnutls_transport_set_ptr);
PHP_FUNCTION(gnutls_x509_crt_init);
PHP_FUNCTION(gnutls_x509_crt_deinit);
PHP_FUNCTION(gnutls_x509_crt_export);
PHP_FUNCTION(gnutls_x509_crt_get_dn);
PHP_FUNCTION(gnutls_x509_crt_get_version);
PHP_FUNCTION(gnutls_x509_crt_get_issuer);
PHP_FUNCTION(gnutls_x509_crt_get_activation_time);
PHP_FUNCTION(gnutls_x509_crt_get_expiration_time);
PHP_FUNCTION(gnutls_x509_crt_get_serial);
PHP_FUNCTION(gnutls_x509_crt_get_signature);
PHP_FUNCTION(gnutls_x509_crt_get_signature_algorithm);
PHP_FUNCTION(gnutls_x509_crt_import);
PHP_FUNCTION(gnutls_x509_crt_check_hostname);
PHP_FUNCTION(gnutls_x509_crt_print);
PHP_FUNCTION(gnutls_x509_dn_init);
PHP_FUNCTION(gnutls_x509_dn_deinit);

/*
** PHP Sockets does not provide a way to ask it for the underlying file description for the socket, so we're
** going to have to accept a socket resource and get it ourselves.
**
** The following structure is taken from ext/sockets/ php_sockets.h
**
** If this structure changes in socket extension, bad things will happen.
*/
#define php_sockets_le_socket_name "Socket"

#ifndef PHP_WIN32
typedef int PHP_SOCKET;
# define PHP_SOCKETS_API PHPAPI
#else
# define PHP_SOCKETS_API __declspec(dllexport)
typedef SOCKET PHP_SOCKET;
#endif

typedef struct {
	PHP_SOCKET bsd_socket;
	int	type;
	int	error;
	int	blocking;
} php_socket;
        
#ifdef PHP_WIN32 
struct  sockaddr_un { 
	short	sun_family;
	char	sun_path[108];
};
#endif

#else

#define phpext_gnutls_ptr NULL

#endif

#endif
