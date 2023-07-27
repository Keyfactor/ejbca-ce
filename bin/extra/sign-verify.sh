#!/bin/bash

# Create a new user 'Batch' in EJBCA, check 'Batch' processing and choose P12 keystore.
# When the p12 has been created you can convert it to openssl format with the following commands.
# (in these commands the created user was called signer, so the p12 file is called signer.p12)
#
# Openssl command to convert a p12 file to cert and key files in pem
# First cert:
#openssl pkcs12 -in signer.p12 -nodes -nokeys -clcerts -out signer.pem
# Then public key
#openssl x509 -in signer.pem -pubkey -noout > signer.pub
# Then private key:
#openssl pkcs12 -in signer.p12 -nodes -nocerts -out signer.priv

OPENSSL=/usr/bin/openssl
SCRIPTNAME="$(basename "$0")"
OPTION="$1"
# DATE=`date +"%Y-%m-%d"`
# BACKUPDIR=signed_files

if [ "$OPTION" = "sign" ]; then
    PRIVATEKEY="$2"
    FILE="$3"
    SIGNATUREFILE="$4"
    $OPENSSL dgst -sign "$PRIVATEKEY" -sha256 "$FILE" > $SIGNATUREFILE

    exit 0

elif [ "$OPTION" = "verify" ]; then
    PUBLICKEY="$2"
    FILE="$3"
    SIGNATUREFILE="$4"

    $OPENSSL dgst -verify $PUBLICKEY -signature $SIGNATUREFILE -sha256 $FILE
    exit $?

else
    echo "Usage:"
    echo "${SCRIPTNAME} sign <path to private key> <path to file to sign> <path to signature>"
    echo "${SCRIPTNAME} verify <path to public key> <file that IS signed> <file which contains the signature>"
    echo "Return code of verify is 0 if OK and 1 if verify failed"
    exit 0
fi
