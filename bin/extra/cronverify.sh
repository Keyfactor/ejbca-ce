#!/bin/bash

##### Begin configuration #####

# The path where sign-verify.sh is installed
CMD_HOME=/usr/local/ejbca/bin/extra/
# The file that is signed, that we want to verify
SIGNED_FILE=/usr/local/ejbca/bin/extra/README.txt
# the signature create with 'sign-verify.sh sign ...'
SIGNATURE=/usr/local/ejbca/bin/extra/README.txt.sig
# The public key used for verification
PUBKEY=/usr/local/ejbca/bin/extra/signer.pub

# Set to true if you want to log to syslog when verification fails
CALLSYSLOG=true
LOGPRI=local3.err

# Set to true if you want to remove the signed file if verification fails
REMOVE_SIGNED_FILE=true

##### End configuration #####

$CMD_HOME/sign-verify.sh verify $PUBKEY $SIGNED_FILE $SIGNATURE > /dev/null


if [ $? != 0 ]; then
  if [ "$CALLSYSLOG" = "true" ]; then
  echo foo
    logger -p $LOGPRI "Verification of signed file $SIGNED_FILE failed!"
  fi
  if [ "$REMOVE_SIGNED_FILE" = "true" ]; then
  echo bar
    rm $SIGNED_FILE
  fi
fi
