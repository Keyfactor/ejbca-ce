@echo off

set JAVACACERTPASSWD=%1
if %1() == () set JAVACACERTPASSWD=changeit

rem Check for proper settings of environment variables
if "%JBOSS_HOME%" == ""  goto jbosserror
if "%JAVA_HOME%" == ""  goto javaerror

set PATH=%PATH%;%JAVA_HOME%\bin
set JAVA_OPTS=-server -Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=y %JAVA_OPTS%


set CP=.;bin/classes;.\admin.jar;.\lib\ldap.jar;lib\log4j-1.2.7.jar;%JBOSS_HOME%\client\jnp-client.jar;%JBOSS_HOME%\client\jboss-j2ee.jar;%JBOSS_HOME%\client\jbossall-client.jar;%JBOSS_HOME%\client\jboss-client.jar;%JBOSS_HOME%\client\jbosssx-client.jar;%JBOSS_HOME%\client\jboss-common-client.jar;.\lib\bcprov-jdk14-124.jar;.\lib\bcmail-jdk14-124.jar

java %JAVA_OPTS% -cp %CP% se.anatom.ejbca.admin.Install install windows en ejbca jboss tomcat

if NOT ERRORLEVEL 0 goto end

keytool -alias EJBCA-CA -delete -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %JAVACACERTPASSWD%
keytool -alias EJBCA-CA -import -trustcacerts -file tmp\rootca.der -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %JAVACACERTPASSWD%  -noprompt

del tmp\rootca.der

java -cp %CP% se.anatom.ejbca.admin.Install displayendmessage windows en ejbca jboss tomcat

goto end

:jbosserror
echo JBOSS_HOME must be set in order to install sucessfully.
goto end
:javaerror
echo JAVA_HOME must be set in order to install sucessfully.
:end