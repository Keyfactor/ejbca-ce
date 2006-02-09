#!/usr/bin/env bash

# This file is for running the stand-alone OCSP client.
# Build with 'ant ocspclient.jar' and unpack the resulting zip file
# in a directory of your choice. Run this command from within that directory.

# OS specific support.
cygwin=false;
case "`uname`" in
  CYGWIN*) cygwin=true ;;
esac

# Check that JAVA_HOME is set
if [ -f $JAVA_HOME ]; then
    echo "You must set JAVA_HOME before running the OCSP cli."
    exit 1
fi

EJBCA_HOME=..
if [ ! -x ocsp.sh ]
then
EJBCA_HOME=.
fi
# Check that classes exist
if [ ! -f ${EJBCA_HOME}/ocspclient.jar ]
then    
        echo "You must be in the right place to run ocsp client."
        exit 1
fi


# For Cygwin, switch paths to Windows format before running java
if $cygwin; then
  CP=`cygpath --path --windows "$CP"`
fi

exec "$JAVA_HOME/bin/java" -Dlog4j.properties=log4j.properties -jar ocspclient.jar "$@"

