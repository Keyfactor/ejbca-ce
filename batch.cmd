@echo off

rem Check for proper settings of environment variables
if "%JBOSS_HOME%" == ""  goto error

rem JBoss
set CP=.;.\admin.jar;%JBOSS_HOME%\client\jnp-client.jar;%JBOSS_HOME%\client\jbossall-client.jar;%JBOSS_HOME%\client\jboss-client.jar;%JBOSS_HOME%\client\jboss-j2ee.jar;%JBOSS_HOME%\client\jbosssx-client.jar;%JBOSS_HOME%\client\jboss-common-client.jar;.\lib\junit.jar;.\lib\log4j-1.2.7.jar;.\lib\bcprov-jdk14-120.jar;..\..\lib\bcmail-jdk14-120.jar

rem Weblogic
rem set CP=.;.\admin.jar;.\lib\weblogic.jar;.\lib\junit.jar;.\lib\log4j-1.2.7.jar;.\lib\bcprov-jdk14-120.jar;..\..\lib\bcmail-jdk14-120.jar

rem JBoss
java -cp %CP% se.anatom.ejbca.batch.BatchMakeP12 %1 %2

rem Weblogic
rem java -cp %CP% se.anatom.ejbca.batch.BatchMakeP12 %1 %2

goto end
:error 
echo JBOSS_HOME must be set
:end
