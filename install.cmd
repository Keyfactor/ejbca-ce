@echo off

set JAVACACERTPASSWD=%1
if %1() == () set JAVACACERTPASSWD=changeit



set CP=.;.\admin.jar;.\lib\ldap.jar

java -cp %CP% se.anatom.ejbca.admin.Install install windows en ejbca jboss tomcat 

if NOT ERRORLEVEL 0 goto end

keytool -alias EJBCA-CA -delete -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %JAVACACERTPASSWD%
keytool -alias EJBCA-CA -import -trustcacerts -file tmp\rootca.der -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %JAVACACERTPASSWD%

del tmp\rootca.der

java -cp %CP% se.anatom.ejbca.admin.Install displayendmessage windows en ejbca jboss tomcat

:end