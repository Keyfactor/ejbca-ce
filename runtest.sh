#!/bin/sh

# Check for proper settings of environment variables
if [ -f $JBOSS_HOME ]
then
        echo JBOSS_HOME must be set to deploy automagically.
        exit
fi


# JBoss
TEST_CP=.:$JBOSS_HOME/client/jnp-client.jar:$JBOSS_HOME/client/jboss-j2ee.jar:$JBOSS_HOME/client/jbossall-client.jar:$JBOSS_HOME/client/jboss-client.jar:$JBOSS_HOME/client/jbosssx-client.jar:$JBOSS_HOME/client/jboss-common-client.jar:../../lib/junit.jar:../../lib/log4j-1.2.7.jar:../../lib/bcprov-jdk14-122.jar:../../lib/bcmail-jdk14-120.jar:../../lib/httpunit.jar

# Weblogic
#TEST_CP=.:../../lib/weblogic.jar:../../lib/junit.jar:../../lib/log4j-1.2.7.jar:../../lib/bcprov-jdk14-122.jar:../../lib/bcmail-jdk14-120.jar:../../lib/httpunit.jar

# Function to perform HTTP tests instead of regular tests
webtest()
{
    echo Testing webdist web
    java -cp $TEST_CP se.anatom.ejbca.webdist.junit.TestRunner web
    java -cp $TEST_CP se.anatom.ejbca.protocol.junit.TestRunner web
    exit
}

cd src/java

if [ "$1" = "web" ]
then
  webtest
  cd ../..
  exit
fi

echo Testing utils
java -cp $TEST_CP se.anatom.ejbca.util.junit.TestRunner
echo Testing messages
#java -cp $TEST_CP se.anatom.ejbca.protocol.junit.TestRunner
echo Testing ra
java -cp $TEST_CP se.anatom.ejbca.ra.junit.TestRunner
echo Testing ca.auth
java -cp $TEST_CP se.anatom.ejbca.ca.auth.junit.TestRunner
echo Testing ca.store
java -cp $TEST_CP se.anatom.ejbca.ca.store.junit.TestRunner
echo Testing ca.sign
java -cp $TEST_CP se.anatom.ejbca.ca.sign.junit.TestRunner
echo Testing ca.crl
java -cp $TEST_CP se.anatom.ejbca.ca.crl.junit.TestRunner
echo Testing ca.publisher
java -cp $TEST_CP se.anatom.ejbca.ca.publisher.junit.TestRunner
echo Testing batch
java -cp $TEST_CP se.anatom.ejbca.batch.junit.TestRunner


cd ../..



