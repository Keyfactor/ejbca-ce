@echo off

rem Check for proper settings of environment variables
if "%JBOSS_HOME%" == ""  goto error

rem JBoss
set CP=.;.\admin.jar;%JBOSS_HOME%\client\jnp-client.jar;%JBOSS_HOME%\client\jboss-client.jar;%JBOSS_HOME%\client\jboss-j2ee.jar;%JBOSS_HOME%\client\jbosssx-client.jar;%JBOSS_HOME%\client\jboss-common-client.jar;.\lib\junit.jar;.\lib\log4j-1.2.jar;.\lib\jce-jdk13-116.jar

rem Weblogic
rem set CP=.;.\admin.jar;.\lib\weblogic.jar;.\lib\junit.jar;.\lib\log4j-1.2.jar;.\lib\jce-jdk13-116.jar

rem JBoss
java -cp %CP% se.anatom.ejbca.util.JobRunner %1 %2 %3 %4

rem Weblogic
rem java %CP% se.anatom.ejbca.util.JobRunner %1 %2 %3 %4

goto end
:error 
echo JBOSS_HOME must be set
:end
