--TEST--
GnuTLS Core Functions
--SKIPIF--
<?php 
if (!extension_loaded("gnutls")) die("skip"); 
?>
--FILE--
<?php
$host = 'www.google.com';
$port = 443;

var_dump($socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP));

var_dump($session = gnutls_init(GNUTLS_CLIENT));

var_dump(gnutls_transport_set_ptr($session, $socket));

var_dump(socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array("sec" => 1, "usec" => 0)));

var_dump(socket_connect($socket, $host, $port));

var_dump(gnutls_priority_set_direct($session, "NORMAL"));

var_dump($cred = gnutls_certificate_allocate_credentials());

var_dump(gnutls_credentials_set($session, GNUTLS_CRD_CERTIFICATE, $cred));

var_dump(gnutls_handshake($session));

var_dump(gnutls_bye($session, GNUTLS_SHUT_RDWR));

var_dump(gnutls_deinit($session));

var_dump(socket_close($socket));

echo "OK!\n";

?>
--EXPECTF--
resource(%d) of type (Socket)
resource(%d) of type (GnuTLS session)
bool(false)
bool(true)
bool(true)
int(0)
resource(%d) of type (GnuTLS credential)
int(0)
int(0)
int(0)
bool(false)
NULL
OK!
