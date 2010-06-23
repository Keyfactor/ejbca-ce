#!/bin/bash

# 
# Create a key via a PKCS#11 device # 
# Example:
#

if [ -z "$EJBCA_HOME" ] ; then
	EJBCA_FILE="$0" 
	EJBCA_HOME=`echo $(dirname $(dirname $EJBCA_FILE))`
fi

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

#CLASSES=$CLASSES:$APPSRV_HOME/server/default/lib/iaik_jce.jar
#CLASSES=$CLASSES:$APPSRV_HOME/server/default/lib/iaikPkcs11Provider.jar
#CLASSES=$CLASSES:$APPSRV_HOME/server/default/lib/iaikPkcs11Wrapper.jar
#CLASSES=$CLASSES:$EJBCA_HOME/tmp/bin/clientToolBox-classes
# use this instead if you want build from eclipse
#CLASSES=$CLASSES:$EJBCA_HOME/out/classes

if [ ! -f $EJBCA_HOME/dist/clientToolBox/clientToolBox.jar ] ; then
	echo "You have to build the ClientToolBox before running this command."
	exit 1
fi

# Finally run java
#set -x
# -cp $CLASSES 
$JAVACMD -jar $EJBCA_HOME/dist/clientToolBox/clientToolBox.jar PKCS11HSMKeyTool "${@}"
