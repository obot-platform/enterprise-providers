#!/bin/sh
# Prints the TLS certificate of the local PingFederate's runtime engine
# (https://localhost:9031), for the provider's CA Certificate setting. Ping's
# baseline profile uses a self-signed certificate, so the certificate is its
# own CA.
set -eu
openssl s_client -connect localhost:9031 -servername localhost -showcerts </dev/null 2>/dev/null |
	sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p'
