#!/bin/bash

#
# Bruno Bonfils, <asyd@asyd.net>
# January 2007
# 
# Create a key via a netHSM device # 
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
        echo "You must set JAVA_HOME before running the nCipherHSM cli."
        exit 1
    fi
else
    JAVACMD=$JAVA_HOME/bin/java
fi

if [ -z $NFAST_HOME ]; then
        echo "Warning: NFAST_HOME not set, using default to /opt/nfast"
        NFAST_HOME=/opt/nfast
fi

NFAST_JARS=$NFAST_HOME/java/classes

# Add nfast's JARs to classpath
for jar in rsaprivenc.jar nfjava.jar kmjava.jar kmcsp.jar jutils.jar
do
        CLASSES="$CLASSES:$NFAST_JARS/$jar"
done

if [ ! -f $EJBCA_HOME/dist/clientToolBox/clientToolBox.jar ] ; then
	echo "You have to build the ClientToolBox before running this command."
	exit 1
fi

# Finally run java
#set -x
$JAVACMD -cp $CLASSES -jar $EJBCA_HOME/dist/clientToolBox/clientToolBox.jar NCipherHSMKeyTool "${@}"

