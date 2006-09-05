#!/bin/sh
#
# JBoss Control Script
#
# chkconfig: 3 80 20
# description: JBoss EJB Container
# 
# To use this script
# run it as root - it will switch to the specified user
# It loses all console output - use the log.
#
# Here is a little (and extremely primitive) 
# startup/shutdown script for RedHat systems. It assumes 
# that JBoss lives in /usr/local/jboss, it's run by user 
# 'jboss' and JDK binaries are in /usr/local/jdk/bin. All 
# this can be changed in the script itself. 
# Bojan 
#
# Either amend this script for your requirements
# or just ensure that the following variables are set correctly 
# before calling the script

# [ #420297 ] JBoss startup/shutdown for RedHat

#make java is on your path
JAVAPTH=${JAVAPTH:-"/usr/local/jdk/bin"}

#define the classpath for the shutdown class
JBOSSCP=${JBOSSCP:-"$JBOSS_HOME/bin/shutdown.jar:$JBOSS_HOME/client/jnet.jar"}

#define the script to use to start jboss
#JBOSSSH=${JBOSSSH:-"$JBOSS_HOME/bin/run.sh -c all"}
JBOSSSH=${JBOSSSH:-"/opt/nfast/bin/preload $JBOSS_HOME/bin/run.sh"}

CMD_START="$JBOSSSH" 
CMD_STOP="java -classpath $JBOSSCP org.jboss.Shutdown --shutdown"

NFAST_JAR="/opt/nfast/java/classes"
export JBOSS_CLASSPATH="$NFAST_JAR/kmcsp.jar:$NFAST_JAR/kmjava.jar:$NFAST_JAR/nfjava.jar:$NFAST_JAR/rsaprivenc.jar"
#export JAVA_OPTS="-server -Xms128m -Xmx512m -Dsun.rmi.dgc.client.gcInterval=3600000 -Dsun.rmi.dgc.server.gcInterval=3600000 -DCKNFAST_LOADSHARING=0 -DJCECSP_DEBUG=229 -DJCECSP_DEBUGFILE=jceLog"

if [ -z "`echo $PATH | grep $JAVAPTH`" ]; then
  export PATH=$PATH:$JAVAPTH
fi

if [ ! -d "$JBOSS_HOME" ]; then
  echo JBOSS_HOME does not exist as a valid directory : $JBOSS_HOME
  exit 1
fi


echo CMD_START = $CMD_START


case "$1" in
start)
    $CMD_START
    ;;
stop)
    $CMD_STOP
    ;;
*)
    echo "usage: $0 (start|stop|help)"
esac
