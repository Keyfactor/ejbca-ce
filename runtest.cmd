
cd src\java

rem JBoss
set TEST_CP=.;..\..\lib\jnp-client.jar;..\..\lib\jboss-client.jar;..\..\lib\jboss-j2ee.jar;..\..\lib\jbosssx-client.jar;..\..\lib\jboss-common-client.jar;..\..\lib\junit.jar;..\..\lib\log4j-1.2.jar;..\..\lib\jce-jdk13-112.jar

rem Weblogic
rem set TEST_CP=.;..\..\lib\weblogic.jar;..\..\lib\junit.jar;..\..\lib\log4j-1.2.jar;..\..\lib\jce-jdk13-112.jar

echo Testing ra
java -cp %TEST_CP% se.anatom.ejbca.ra.junit.TestRunner
rem java -cp %TEST_CP% se.anatom.ejbca.ra.raadmin.junit.TestRunner
echo Testing ca.auth
java -cp %TEST_CP% se.anatom.ejbca.ca.auth.junit.TestRunner
echo Testing ca.store
java -cp %TEST_CP% se.anatom.ejbca.ca.store.junit.TestRunner
echo Testing ca.sign
java -cp %TEST_CP% se.anatom.ejbca.ca.sign.junit.TestRunner
echo Testing ca.crl
java -cp %TEST_CP% se.anatom.ejbca.ca.crl.junit.TestRunner
echo Testing batch
java -cp %TEST_CP% se.anatom.ejbca.batch.junit.TestRunner

cd ..\..
