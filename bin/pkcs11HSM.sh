#!/bin/bash

# 
# Create a key via a PKCS#11 device # 
# Example:
#

if [ -z $EJBCA_HOME ]; then
	echo "Fatal error: EJBCA_HOME is not set"
	exit 1
fi

if [ -z $JAVA_HOME ]; then
	echo "Fatal error: JAVA_HOME is not set"
fi

if [ -z $JAVA_PKCS11_LIB ]; then
	echo "Fatal error: JAVA_PKCS11_LIB is not set"
	exit 1
fi

CLASSES=$EJBCA_HOME/lib/bcprov-jdk15.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/bcmail-jdk15.jar
CLASSES=$CLASSES:$EJBCA_HOME/tmp/bin/classes
# use this instead if you want build from eclipse
#CLASSES=$CLASSES:$EJBCA_HOME/out/classes

# Prepare arguments
args="`basename $0` $1"
shift
args="$args $JAVA_PKCS11_LIB null pkcs11 $@"

# Finally run java
#set -x
$JAVA_HOME/bin/java -cp $CLASSES org.ejbca.ui.cli.HSMKeyTool $args
