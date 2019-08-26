#!/bin/bash

# 
# Toolbox for EJBCA clients # 
#

if [ -z ${TOOLBOX_HOME} ] ; then
	TOOLBOX_HOME=`echo $(dirname ${0})`
fi

if [ -z ${JAVA_HOME} ]; then
	javaCmd="java"
else
	javaCmd=${JAVA_HOME}/bin/java
fi


# Finally run java
#set -x
${javaCmd} ${JAVA_OPT} -cp "$TOOLBOX_HOME/clientToolBox.jar:${TOOLBOX_HOME}/ext/*" org.ejbca.ui.cli.ClientToolBox "${@}"
