@echo off
rem This script sets up the administrative web interface with client cert authentication.
rem Usage: setup-adminweb <DN Tomcat Server Cert> <Tomcat keystore passwd> <SuperAdmin password> <java cacert keystore passwd>

if %1() == () goto error
if %2() == () goto error
if %3() == () goto error
if %4() == () goto error

call ra adduser tomcat %2 %1 null null 1 3

rem call ra adduser superadmin %3 "CN=SuperAdmin" null null 65 2

rem call ra setclearpwd tomcat %2

rem call ra setclearpwd superadmin %3

rem call batch

rem copy p12\tomcat.jks %JBOSS_HOME%\.keystore

rem call ca getrootcert tmp\rootca.der

keytool -alias EJBCA-CA -delete -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %4
keytool -alias EJBCA-CA -import -trustcacerts -file tmp\rootca.der -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %4

del tmp\rootca.der

set CP=.;.\admin.jar;.\lib\regexp1_0_0.jar

set TOMCAT_XML=tomcat41-service.xml
if exist "%JBOSS_HOME%\server\default\deploy\tomcat4-service.xml" set TOMCAT_XML=tomcat4-service.xml

rem java -cp %CP% se.anatom.ejbca.util.TomcatServiceXMLPasswordReplace src\adminweb\WEB-INF\%TOMCAT_XML% tmp\%TOMCAT_XML% %2

rem copy tmp\%TOMCAT_XML% %JBOSS_HOME%\server\default\deploy\%TOMCAT_XML%

rem del tmp\%TOMCAT_XML%

goto end
:error
echo "Usage: setup-adminweb <DN Tomcat Server Cert> <Tomcat keystore passwd> <SuperAdmin password> <java cacert keystore passwd>"
:end
