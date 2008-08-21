#!/bin/bash

# 
# Create a key via a PKCS#11 device # 
# Example:
#

if [ -z ${TOOLBOX_HOME} ] ; then
	TOOLBOX_HOME=`echo $(dirname ${0})`
fi

JAVACMD=`which java`
# Check that JAVA_HOME is set
if [ -z ${JAVA_HOME} ]; then
    if [ -z ${JAVACMD} ]
    then
        echo "You must set JAVA_HOME before running the EJBCA cli."
        exit 1
    fi
else
    JAVACMD=${JAVA_HOME}/bin/java
fi

CLASSES=${CLASSES}:${TOOLBOX_HOME}/clientToolBox.jar:${TOOLBOX_HOME}/properties

if [ -d ${TOOLBOX_HOME} ] ; then
	for i in ${TOOLBOX_HOME}/lib/*.jar ; do
		CLASSES=${CLASSES}:${i}
    done
fi

if [ -z ${NFAST_HOME} ]; then
    NFAST_HOME=~nfast
fi
NFAST_JARS=$NFAST_HOME/java/classes
if [ -d ${NFAST_JARS} ] ; then
    for jar in rsaprivenc.jar nfjava.jar kmjava.jar kmcsp.jar jutils.jar; do
        CLASSES="$CLASSES:$NFAST_JARS/$jar"
    done
fi

# Finally run java
set -x
${JAVACMD} -cp ${CLASSES} org.ejbca.ui.cli.HSMKeyTool ${@}

