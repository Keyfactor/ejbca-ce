#!/bin/sh

# Check for proper settings of environment variables
if [ -f $JBOSS_HOME ]
then
        echo JBOSS_HOME must be set to deploy automagically.
        exit
fi

cd src/java

# JBoss
TEST_CP=.:$JBOSS_HOME/client/jnp-client.jar:$JBOSS_HOME/client/jboss-j2ee.jar:$JBOSS_HOME/client/jboss-client.jar:$JBOSS_HOME/client/jbosssx-client.jar:$JBOSS_HOME/client/jboss-common-client.jar:../../lib/junit.jar:../../lib/log4j-1.2.jar:../../lib/jce-jdk13-117.jar:../../lib/bcmail-jdk13-117.jar

# Weblogic
#TEST_CP=.:../../lib/weblogic.jar:../../lib/junit.jar:../../lib/log4j-1.2.jar:../../lib/jce-jdk13-117.jar:../../lib/bcmail-jdk13-117.jar

echo Testing utils
#java -cp $TEST_CP se.anatom.ejbca.util.junit.TestRunner
echo Testing messages
java -cp $TEST_CP se.anatom.ejbca.protocol.junit.TestRunner
echo Testing ra
#java -cp $TEST_CP se.anatom.ejbca.ra.junit.TestRunner
echo Testing ca.auth
#java -cp $TEST_CP se.anatom.ejbca.ca.auth.junit.TestRunner
echo Testing ca.store
#java -cp $TEST_CP se.anatom.ejbca.ca.store.junit.TestRunner
echo Testing ca.sign
#java -cp $TEST_CP se.anatom.ejbca.ca.sign.junit.TestRunner
echo Testing ca.crl
#java -cp $TEST_CP se.anatom.ejbca.ca.crl.junit.TestRunner
echo Testing batch
#java -cp $TEST_CP se.anatom.ejbca.batch.junit.TestRunner

cd ../..

