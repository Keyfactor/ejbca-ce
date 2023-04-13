#!/bin/sh

# Manual classpath to include all JDBC drivers we put in 'endorsed'
export MYCP=`dirname "$0"`/ejbca-ws-cli.jar:`dirname "$0"`/endorsed/*
#echo $MYCP 

# Memory settings can be specified using parameters like: JAVA_OPT="-Xms20480m -Xmx20480m -XX:MaxPermSize=384m" run.sh ....
if [ "x${JAVA_OPT}" = "x" ] ; then
    echo
else
    echo Using JAVA_OPT: ${JAVA_OPT}
fi

java ${JAVA_OPT} -Dlog4j1.compatibility=true -cp $MYCP org.ejbca.core.protocol.ws.client.cvcwscli "$@"
