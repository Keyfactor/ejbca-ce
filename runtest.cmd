
cd src\java

rem Check for proper settings of environment variables
if "%JBOSS_HOME%" == ""  goto error

rem JBoss
set TEST_CP=.;%JBOSS_HOME%\client\jnp-client.jar;%JBOSS_HOME%\client\jbossall-client.jar;%JBOSS_HOME%\client\jboss-client.jar;%JBOSS_HOME%\client\jboss-j2ee.jar;%JBOSS_HOME%\client\jbosssx-client.jar;%JBOSS_HOME%\client\jboss-common-client.jar;..\..\lib\junit.jar;..\..\lib\log4j-1.2.7.jar;..\..\lib\bcprov-jdk14-122.jar;..\..\lib\bcmail-jdk14-122.jar;..\..\lib\httpunit.jar

rem Weblogic
rem set TEST_CP=.;..\..\lib\weblogic.jar;..\..\lib\junit.jar;..\..\lib\log4j-1.2.7.jar;..\..\lib\bcprov-jdk14-122.jar;..\..\lib\bcmail-jdk14-122.jar

if "%1" == "web"  goto webtest

echo Testing ca
java -cp %TEST_CP% se.anatom.ejbca.ca.caadmin.junit.TestRunnerStart
echo Testing utils
java -cp %TEST_CP% se.anatom.ejbca.util.junit.TestRunner
echo Testing messages
rem java -cp %TEST_CP% se.anatom.ejbca.protocol.junit.TestRunner
echo Testing raadmin
java -cp %TEST_CP% se.anatom.ejbca.ra.raadmin.junit.TestRunner
echo Testing ra
java -cp %TEST_CP% se.anatom.ejbca.ra.junit.TestRunner
echo Testing ca.auth
java -cp %TEST_CP% se.anatom.ejbca.ca.auth.junit.TestRunner
echo Testing ca.store
java -cp %TEST_CP% se.anatom.ejbca.ca.store.junit.TestRunner
echo Testing ca.sign
java -cp %TEST_CP% se.anatom.ejbca.ca.sign.junit.TestRunner
echo Testing ca.crl
java -cp %TEST_CP% se.anatom.ejbca.ca.crl.junit.TestRunner
echo Testing ca.publisher
java -cp %TEST_CP% se.anatom.ejbca.ca.publisher.junit.TestRunner
echo Testing batch
java -cp %TEST_CP% se.anatom.ejbca.batch.junit.TestRunner
echo Testing log
java -cp %TEST_CP% se.anatom.ejbca.log.junit.TestRunner
echo Testing keyrecovery
java -cp %TEST_CP% se.anatom.ejbca.keyrecovery.junit.TestRunner
echo Testing hardtoken
java -cp %TEST_CP% se.anatom.ejbca.hardtoken.junit.TestRunner

java -cp %TEST_CP% se.anatom.ejbca.ca.caadmin.junit.TestRunnerEnd

goto end

:webtest
echo Testing webdist web
java -cp %TEST_CP% se.anatom.ejbca.webdist.junit.TestRunner web
java -cp %TEST_CP% se.anatom.ejbca.protocol.junit.TestRunner web
goto end

:error 
echo JBOSS_HOME must be set
:end
cd ..\..

