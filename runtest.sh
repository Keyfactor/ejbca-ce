#!/bin/sh

cd src/java
echo Testing ra
java -cp .:../../lib/junit.jar:../../lib/jnp-client.jar:../../lib/jboss-client.jar:../../lib/jboss-jaas.jar:../../lib/log4j.jar:../../lib/bcprov.jar se.anatom.ejbca.ra.junit.TestRunner
echo Testing ca.auth
java -cp .:../../lib/junit.jar:../../lib/jnp-client.jar:../../lib/jboss-client.jar:../../lib/jboss-jaas.jar:../../lib/log4j.jar:../../lib/bcprov.jar se.anatom.ejbca.ca.auth.junit.TestRunner
echo Testing ca.store
java -cp .:../../lib/junit.jar:../../lib/jnp-client.jar:../../lib/jboss-client.jar:../../lib/jboss-jaas.jar:../../lib/log4j.jar:../../lib/bcprov.jar se.anatom.ejbca.ca.store.junit.TestRunner
echo Testing ca.sign
java -cp .:../../lib/junit.jar:../../lib/jnp-client.jar:../../lib/jboss-client.jar:../../lib/jboss-jaas.jar:../../lib/log4j.jar:../../lib/bcprov.jar se.anatom.ejbca.ca.sign.junit.TestRunner
echo Testing ca.crl
java -cp .:../../lib/junit.jar:../../lib/jnp-client.jar:../../lib/jboss-client.jar:../../lib/jboss-jaas.jar:../../lib/log4j.jar:../../lib/bcprov.jar se.anatom.ejbca.ca.crl.junit.TestRunner
echo Testing batch
java -cp .:../../lib/junit.jar:../../lib/jnp-client.jar:../../lib/jboss-client.jar:../../lib/jboss-jaas.jar:../../lib/log4j.jar:../../lib/bcprov.jar se.anatom.ejbca.batch.junit.TestRunner
cd ../..
