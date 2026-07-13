#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssl ca-certificates

PKI_DIR=/etc/nato-pki
rm -rf "${PKI_DIR}"
mkdir -p "${PKI_DIR}/newcerts"
cd "${PKI_DIR}"
touch index.txt
printf '1000\n' > serial
printf '1000\n' > crlnumber

cat > openssl.cnf <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /etc/nato-pki
database          = $dir/index.txt
new_certs_dir     = $dir/newcerts
certificate       = $dir/ca.crt
private_key       = $dir/ca.key
serial            = $dir/serial
crlnumber         = $dir/crlnumber
default_md        = sha256
default_days      = 3650
default_crl_days  = 3650
policy            = policy_any
unique_subject    = no
copy_extensions   = copy

[ policy_any ]
commonName = supplied

[ req ]
distinguished_name = req_dn
prompt = no

[ req_dn ]
commonName = NATO Benchmark Device CA

[ server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:192.168.100.13,DNS:s16-device-api

[ client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca.key -out ca.crt -days 3650 \
  -subj '/CN=NATO Benchmark Device CA' >/dev/null 2>&1

openssl req -new -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj '/CN=s16-device-api' >/dev/null 2>&1
openssl ca -batch -config openssl.cnf -extensions server_cert \
  -in server.csr -out server.crt >/dev/null 2>&1

openssl req -new -newkey rsa:2048 -nodes \
  -keyout device-a.key -out device-a.csr \
  -subj '/CN=device-a' >/dev/null 2>&1
openssl ca -batch -config openssl.cnf -extensions client_cert \
  -in device-a.csr -out device-a.crt >/dev/null 2>&1

# Device B receives a different certificate but intentionally reuses device
# A's private key. This gives both identities the same public-key fingerprint.
openssl req -new -key device-a.key -out device-b.csr \
  -subj '/CN=device-b' >/dev/null 2>&1
openssl ca -batch -config openssl.cnf -extensions client_cert \
  -in device-b.csr -out device-b.crt >/dev/null 2>&1
cp device-a.key device-b.key

openssl ca -batch -config openssl.cnf -revoke device-b.crt >/dev/null 2>&1
openssl ca -batch -config openssl.cnf -gencrl -out ca.crl >/dev/null 2>&1

for device in device-a device-b; do
  openssl x509 -in "${device}.crt" -pubkey -noout \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | sha256sum | awk '{print $1}' > "${device}.public-key.sha256"
done

chmod 0600 ./*.key
chmod 0644 ./*.crt ./*.crl ./*.sha256
echo PKI_OK
