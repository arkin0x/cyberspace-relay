#!/bin/bash
# How server/nwc's NIP-04 test vector was made: OpenSSL only (ECDH on
# secp256k1 gives the shared x; AES-256-CBC with PKCS#7 padding), so the
# vector does not come from the code it tests.
openssl ecparam -name secp256k1 -genkey -noout -out a.pem
openssl ecparam -name secp256k1 -genkey -noout -out b.pem
openssl ec -in b.pem -pubout -out bpub.pem
openssl pkeyutl -derive -inkey a.pem -peerkey bpub.pem -out shared.bin
SH=$(od -An -tx1 -v shared.bin | tr -d ' \n')
printf '%s' '{"method":"lookup_invoice","params":{"payment_hash":"ab"}}' |
  openssl enc -aes-256-cbc -K "$SH" -iv 000102030405060708090a0b0c0d0e0f | base64 -w0
