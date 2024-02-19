#!/usr/bin/env bash
source ./.env
openssl req \
  -new \
  -newkey rsa:4096 \
  -days 3650 \
  -nodes \
  -x509 \
  -subj "/C=US/ST=CA/L=SF/O=demo/CN=sdk-demo" \
  -keyout sdk_demo.key \
  -out sdk_demo.cert

openssl req \
  -new \
  -newkey rsa:4096 \
  -days 3650 \
  -nodes \
  -x509 \
  -subj "/C=US/ST=CA/L=SF/O=demo/CN=scimgateway" \
  -keyout scimgateway.key \
  -out scimgateway.cert

openssl pkcs12 -export -in sdk_demo.cert -inkey sdk_demo.key -out sdk_demo.p12 -password pass:$KEYSTORE_PASSWORD -name demossl
openssl pkcs12 -certpbe AES-256-CBC -keypbe AES-256-CBC -export -in scimgateway.cert -inkey scimgateway.key -out scimgateway.p12 -password pass:$KEYSTORE_PASSWORD -name demossl

mv ./sdk_demo.cert ./container_opp_agent
mv ./scimgateway.cert ./container_opp_agent

mv ./sdk_demo.p12 ./container_sdk_demo
mv ./scimgateway.p12 ./container_scimgateway

echo $'\n' >> ./.env
echo "LDAP_ADMIN_ENCRYPTION_KEY=base64:$(openssl rand -base64 32)" >> ./.env

docker compose build --no-cache
