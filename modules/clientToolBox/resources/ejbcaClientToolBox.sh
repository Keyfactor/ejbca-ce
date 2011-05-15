#!/bin/bash

# 
# Toolbox for EJBCA clients # 
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

if [ -z ${NFAST_HOME} ]; then
    NFAST_HOME=~nfast
fi
NFAST_JARS=$NFAST_HOME/java/classes
if [ -d ${NFAST_JARS} ] ; then
    for jar in rsaprivenc.jar nfjava.jar kmjava.jar kmcsp.jar jutils.jar; do
        CLASSES="$CLASSES:$NFAST_JARS/$jar"
    done
fi

endorsed="-Djava.endorsed.dirs=${TOOLBOX_HOME}/endorsed"
if [ "x${JAVA_OPT}" = "x" ] ; then
	JAVA_OPT=${endorsed}
else
	JAVA_OPT="${JAVA_OPT} ${endorsed}"
fi
# Finally run java
#set -x
if [ "x$CLASSES" = "x" ] ; then
	${JAVACMD} ${JAVA_OPT} -jar $TOOLBOX_HOME/clientToolBox.jar "${@}"
else
	${JAVACMD} ${JAVA_OPT} -cp ${CLASSES} -jar $TOOLBOX_HOME/clientToolBox.jar "${@}"
fi
