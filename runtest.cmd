
cd src\java

rem JBoss
set TEST_CP=.;..\..\lib\jnp-client.jar;..\..\lib\jboss-client.jar;..\..\lib\jboss-j2ee.jar;..\..\lib\jbosssx-client.jar;..\..\lib\jboss-common-client.jar;..\..\lib\junit.jar;..\..\lib\log4j-1.2.jar;..\..\lib\jce-jdk13-112.jar

rem Weblogic
rem set TEST_CP=.;..\..\lib\weblogic.jar;..\..\lib\junit.jar;..\..\lib\log4j-1.2.jar;..\..\lib\jce-jdk13-112.jar

echo Testing ra
rem java -cp %TEST_CP% se.anatom.ejbca.ra.junit.TestRunner
java -cp %TEST_CP% se.anatom.ejbca.ra.raadmin.junit.TestRunner
echo Testing ca.auth
rem java -cp %TEST_CP% se.anatom.ejbca.ca.auth.junit.TestRunner
echo Testing ca.store
rem java -cp %TEST_CP% se.anatom.ejbca.ca.store.junit.TestRunner
echo Testing ca.sign
rem java -cp %TEST_CP% se.anatom.ejbca.ca.sign.junit.TestRunner
echo Testing ca.crl
rem java -cp %TEST_CP% se.anatom.ejbca.ca.crl.junit.TestRunner
echo Testing batch
rem java -cp %TEST_CP% se.anatom.ejbca.batch.junit.TestRunner

cd ..\..
