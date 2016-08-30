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


if [ -z ${JAVA_EXT} ] ; then
	#assume that the java executable (not symlink) is in the $JAVA_HOME/jre/bin directory.
	jreHome=$(dirname $(dirname $(readlink -f $(which ${javaCmd}))))

	if [ ! -d ${jreHome}/lib/ext ] ; then
		#wrong in previous assumption. New assumption $JAVA_HOME/bin
		jreHome=${jreHome}/jre
	fi

	if [ ! -d ${jreHome}/lib/ext ] ; then
		echo "Can not find the ext directory"
		exit
	fi

	JAVA_EXT="${jreHome}/lib/ext:/usr/java/packages/lib/ext:${TOOLBOX_HOME}/ext"
fi

JAVA_OPT="${JAVA_OPT} -Djava.ext.dirs=${JAVA_EXT}"

# Finally run java
#set -x
${javaCmd} ${JAVA_OPT} -jar $TOOLBOX_HOME/clientToolBox.jar "${@}"
