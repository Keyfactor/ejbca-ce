#!/bin/sh

cd src/java

# JBoss
TEST_CP=.:../../lib/junit.jar:../../lib/jnp-client.jar:../../lib/jboss-client.jar:../../lib/jboss-jaas.jar:../../lib/log4j.jar:../../lib/jce-jdk13-112.jar

# Weblogic
#TEST_CP=.:../../lib/junit.jar:../../lib/weblogic.jar:../../lib/log4j.jar:../../lib/jce-jdk13-112.jar

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
echo Testing batch
java -cp $TEST_CP se.anatom.ejbca.batch.junit.TestRunner

cd ../..
