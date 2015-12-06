#!/bin/bash

# 
# Toolbox for EJBCA clients # 
#

if [ -z ${TOOLBOX_HOME} ] ; then
	TOOLBOX_HOME=`echo $(dirname ${0})`
fi

# Check that JAVA_HOME is set
if [ "x${JAVA_HOME}" = "x" ]; then
	javaCmd="java"
	JAVA_HOME=$(dirname $(dirname $(readlink -f $(which ${javaCmd}))))
else
    javaCmd=${JAVA_HOME}/bin/java
fi

if [ "x${JAVA_EXT}" = "x" ] ; then
	JAVA_EXT="${JAVA_HOME}/lib/ext:/usr/java/packages/lib/ext:${TOOLBOX_HOME}/ext"
fi

JAVA_OPT="${JAVA_OPT} -Djava.ext.dirs=${JAVA_EXT}"

# Finally run java
set -x
${javaCmd} ${JAVA_OPT} -jar $TOOLBOX_HOME/clientToolBox.jar "${@}"
