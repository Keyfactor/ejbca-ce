@echo off

set JAVACACERTPASSWD=%1
if %1() == () set JAVACACERTPASSWD=changeit

rem Check for proper settings of environment variables
if "%JBOSS_HOME%" == ""  goto jbosserror
if "%JAVA_HOME%" == ""  goto javaerror


rem check for java in path

java -version
if NOT ERRORLEVEL 0 goto javanotfound


set CP=.;.\admin.jar;.\lib\ldap.jar;%JBOSS_HOME%\client\jnp-client.jar;%JBOSS_HOME%\client\jboss-j2ee.jar;%JBOSS_HOME%\client\jbossall-client.jar;%JBOSS_HOME%\client\jboss-client.jar;%JBOSS_HOME%\client\jbosssx-client.jar;%JBOSS_HOME%\client\jboss-common-client.jar

java -cp %CP% se.anatom.ejbca.admin.Install install windows en ejbca jboss 

if NOT ERRORLEVEL 0 goto end

%JAVA_HOME%\bin\keytool -alias EJBCA-CA -delete -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %JAVACACERTPASSWD%
%JAVA_HOME%\bin\keytool -alias EJBCA-CA -import -trustcacerts -file tmp\rootca.der -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %JAVACACERTPASSWD%

del tmp\rootca.der

java -cp %CP% se.anatom.ejbca.admin.Install displayendmessage windows en ejbca jboss

goto end


:javanotfound
echo cannot find java jvm. Please add it to your path.

:jbosserror
echo JBOSS_HOME must be set in order to install sucessfully.
goto end
:javaerror
echo JAVA_HOME must be set in order to install sucessfully.
:end