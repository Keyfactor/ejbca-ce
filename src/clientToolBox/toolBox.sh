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
if [ ! -n "${JAVA_HOME}" ]; then
    if [ ! -n "${JAVACMD}" ]
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


# Finally run java
set -x
${JAVACMD} -cp ${CLASSES} org.ejbca.ui.cli.HSMKeyTool ${@}

