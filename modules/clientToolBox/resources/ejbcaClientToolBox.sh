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

# Temporary file to disable logging to  java.util.logging
echo "handlers=" > java-util-logging.properties

# Finally run java
#set -x
${javaCmd} ${JAVA_OPT} --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED -Dlog4j1.compatibility=true -Djava.util.logging.config.file=java-util-logging.properties -cp "$TOOLBOX_HOME/clientToolBox.jar:${TOOLBOX_HOME}/ext/*" org.ejbca.ui.cli.ClientToolBox "${@}"

rm -rf java-util-logging.properties
