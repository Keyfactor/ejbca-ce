#!/bin/sh
IFS=

# Check for proper settings of environment variables
if [ -f $JBOSS_HOME ]
then
        echo JBOSS_HOME must be set.
        exit
fi

# JBoss
CP=.:./admin.jar:$JBOSS_HOME/client/jnp-client.jar:$JBOSS_HOME/client/jboss-j2ee.jar:$JBOSS_HOME/client/jboss-client.jar:$JBOSS_HOME/client/jbosssx-client.jar:$JBOSS_HOME/client/jboss-common-client.jar:lib/junit.jar:lib/log4j-1.2.jar:lib/jce-jdk13-117.jar

# Weblogic
#CP=.:./admin.jar:./lib/weblogic.jar:./lib/junit.jar:./lib/log4j-1.2.jar:./lib/jce-jdk13-117.jar

# JBoss
java -cp $CP se.anatom.ejbca.admin.ra $1 $2 $3 $4 $5 $6 $7 $8 $9 $10

# Weblogic
#java -cp $CP se.anatom.ejbca.admin.ra $1 $2 $3 $4 $5 $6 $7 $8 $9 $10
