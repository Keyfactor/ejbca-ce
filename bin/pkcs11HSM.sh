#!/bin/bash

# 
# Create a key via a PKCS#11 device # 
# Example:
#

if [ -z "$EJBCA_HOME" ] ; then
	EJBCA_FILE="$0" 
	EJBCA_HOME=`echo $(dirname $(dirname $EJBCA_FILE))`
fi

#if [ -z $EJBCA_HOME ]; then
#	echo "Fatal error: EJBCA_HOME is not set"
#	exit 1
#fi

JAVACMD=`which java`
# Check that JAVA_HOME is set
if [ ! -n "$JAVA_HOME" ]; then
    if [ ! -n "$JAVACMD" ]
    then
        echo "You must set JAVA_HOME before running the EJBCA cli."
        exit 1
    fi
else
    JAVACMD=$JAVA_HOME/bin/java
fi

CLASSES=$EJBCA_HOME/lib/bcprov-jdk15.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/bcmail-jdk15.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/cert-cvc.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/jline-0.9.94.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/log4j.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/commons-lang-2.4.jar
#CLASSES=$CLASSES:$APPSRV_HOME/server/default/lib/iaik_jce.jar
#CLASSES=$CLASSES:$APPSRV_HOME/server/default/lib/iaikPkcs11Provider.jar
#CLASSES=$CLASSES:$APPSRV_HOME/server/default/lib/iaikPkcs11Wrapper.jar
CLASSES=$CLASSES:$EJBCA_HOME/tmp/bin/classes
# use this instead if you want build from eclipse
#CLASSES=$CLASSES:$EJBCA_HOME/out/classes

# Finally run java
#set -x
$JAVACMD -cp $CLASSES org.ejbca.ui.cli.ClientToolBox PKCS11HSMKeyTool "${@}"
