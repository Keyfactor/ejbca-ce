#!/bin/bash
#
# JBoss Control Script
#

#make java is on your path
JAVAPTH=${JAVAPTH:-"$JBOSS_HOME/bin"}

#define the classpath for the shutdown class
JBOSSCP=${JBOSSCP:-"$JBOSS_HOME/bin/shutdown.jar:$JBOSS_HOME/client/jnet.jar"}

#define the script to use to start jboss
#JBOSSSH=${JBOSSSH:-"$JBOSS_HOME/bin/run.sh -c all"}
if [ "$1" != "-np" ]; then
	JBOSSSH=${JBOSSSH:-"/opt/nfast/bin/preload $JBOSS_HOME/bin/run.sh"}
else
	shift
	JBOSSSH=${JBOSSSH:-"$JBOSS_HOME/bin/run.sh"}
fi
CMD_START="$JBOSSSH" 
CMD_STOP="java -classpath $JBOSSCP org.jboss.Shutdown --shutdown"

NFAST_JAR="/opt/nfast/java/classes"
export JBOSS_CLASSPATH="$NFAST_JAR/kmcsp.jar:$NFAST_JAR/kmjava.jar:$NFAST_JAR/nfjava.jar:$NFAST_JAR/rsaprivenc.jar"
#export JAVA_OPTS="-server -Xms128m -Xmx512m -Dsun.rmi.dgc.client.gcInterval=3600000 -Dsun.rmi.dgc.server.gcInterval=3600000 -DCKNFAST_LOADSHARING=0 -DJCECSP_DEBUG=229 -DJCECSP_DEBUGFILE=jceLog"

if ! echo "$PATH" | grep -q "$JAVAPTH"; then
  export PATH=$PATH:$JAVAPTH
fi

if [ ! -d "$JBOSS_HOME" ]; then
  echo "JBOSS_HOME does not exist as a valid directory : ${JBOSS_HOME}"
  exit 1
fi


echo "CMD_START = ${CMD_START}"


case "$1" in
  start)
    shift
    $CMD_START "$@"
    ;;
  stop)
    $CMD_STOP
    ;;
  *)
    echo "usage: $0 ([-np] start|stop|help)"
    echo " -np   Run without pre-load"
esac
