@echo off

set JAVACACERTPASSWD= %1
if %1() == () set JAVACACERTPASSWD=changeit


set CP=.;.\admin.jar;.\lib\ldap.jar

java -cp %CP% se.anatom.ejbca.admin.Install windows en ejbca jboss tomcat

keytool -alias EJBCA-CA -delete -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %5
keytool -alias EJBCA-CA -import -trustcacerts -file tmp\rootca.der -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %5

del tmp\rootca.der

java -cp %CP% se.anatom.ejbca.admin.Install displayendmessage unix en ejbca jboss tomcat

:end