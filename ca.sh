#!/bin/sh
IFS=

# Check for proper settings of environment variables
if [ -f $JBOSS_HOME ]
then
        echo JBOSS_HOME must be set.
        exit
fi

# JBoss
CP=.:bin/classes:./admin.jar:$JBOSS_HOME/client/jnp-client.jar:$JBOSS_HOME/client/jboss-j2ee.jar:$JBOSS_HOME/client/jbossall-client.jar:$JBOSS_HOME/client/jboss-client.jar:$JBOSS_HOME/client/jbosssx-client.jar:$JBOSS_HOME/client/jboss-common-client.jar:lib/junit.jar:lib/log4j-1.2.7.jar:lib/bcprov-jdk14-124.jar:lib/bcmail-jdk14-124.jar

# Weblogic
#CP=.:./admin.jar:./lib/weblogic.jar:./lib/junit.jar:./lib/log4j-1.2.7.jar:./lib/bcprov-jdk14-124.jar:./lib/bcmail-jdk14-124.jar

# JBoss
java -cp $CP se.anatom.ejbca.admin.ca $*

# Weblogic
#java -cp $CP se.anatom.ejbca.admin.ca $*
