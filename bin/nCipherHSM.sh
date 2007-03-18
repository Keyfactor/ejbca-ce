#!/bin/bash

#
# Bruno Bonfils, <asyd@asyd.net>
# January 2007
# 
# Create a key via a netHSM device # 
# Example:
#

if [ -z $EJBCA_HOME ]; then
        echo "Fatal error: EJBCA_HOME is not set"
        exit 1
fi

if [ -z $JAVA_HOME ]; then
        echo "Fatal error: JAVA_HOME is not set"
fi

if [ -z $NFAST_HOME ]; then
        echo "Warning: NFAST_HOME not set, using default to /opt/nfast"
        NFAST_HOME=/opt/nfast
fi

NFAST_JARS=$NFAST_HOME/java/classes

CLASSES=$EJBCA_HOME/lib/bcprov-jdk15.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/bcmail-jdk15.jar
CLASSES=$CLASSES:$EJBCA_HOME/tmp/bin/classes
# use this instead if you want build from eclipse
#CLASSES=$CLASSES:$EJBCA_HOME/out/classes

# Add nfast's JARs to classpath
for jar in rsaprivenc.jar nfjava.jar kmjava.jar kmcsp.jar jutils.jar
do
        CLASSES="$CLASSES:$NFAST_JARS/$jar"
done

# Prepare arguments
args="`basename $0` $1"
shift
args="$args com.ncipher.provider.km.nCipherKM com.ncipher.fixup.provider.nCipherRSAPrivateEncrypt nCipher.sworld $@"

# Finally run java
#set -x
$JAVA_HOME/bin/java -cp $CLASSES org.ejbca.ui.cli.HSMKeyTool $args
