#!/bin/sh

echo "Generate key"
openssl genrsa -des3 -out $1.key 4096
echo "Create CSR"
openssl req -new -key $1.key -out $1.csr
echo "Get CSR signed by CA"
openssl x509 -req -in $1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $1.crt -days 365 -sha256
echo "Convert to P12 for Keychain Access"
openssl pkcs12 -export -in $1.crt -inkey $1.key -out $1.p12 -name "$2"