@echo off
rem This script sets up the administrative web interface with client cert authentication.
rem Usage: setup-adminweb <CA Name> <DN Server Cert> <keystore passwd> <SuperAdmin password> <java cacert keystore passwd>

if %1() == () goto error
if %2() == () goto error
if %3() == () goto error
if %4() == () goto error

call ra adduser tomcat %3 %2 null %1 null 1 3

call ra adduser superadmin %4 "CN=SuperAdmin" null %1 null 65 2

call ra setclearpwd tomcat %3

call ra setclearpwd superadmin %4

call batch

copy p12\tomcat.jks %JBOSS_HOME%\bin\.keystore

call ca getrootcert %1 tmp\rootca.der -der

keytool -alias EJBCA-CA -delete -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %5
keytool -alias EJBCA-CA -import -trustcacerts -file tmp\rootca.der -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %5

rem del tmp\rootca.der

set CP=.;.\admin.jar

set SERVER_XML=tomcat41-service.xml
if exist "%JBOSS_HOME%\server\default\deploy\tomcat4-service.xml" set SERVER_XML=tomcat4-service.xml
if exist "%JBOSS_HOME%\server\default\deploy\tomcat41-service.xml" set SERVER_XML=tomcat41-service.xml
if exist "%JBOSS_HOME%\server\default\deploy\jbossweb.sar\META-INF\jboss-service.xml" set SERVER_XML=jetty.xml
if exist "%JBOSS_HOME%\server\default\deploy\jbossweb-jetty.sar\META-INF\jboss-service.xml" set SERVER_XML=jetty32.xml

java -cp %CP% se.anatom.ejbca.util.TomcatServiceXMLPasswordReplace src\adminweb\WEB-INF\%SERVER_XML% tmp\%SERVER_XML% %3

if exist "%JBOSS_HOME%\server\default\deploy\tomcat4-service.xml" copy tmp\%SERVER_XML% %JBOSS_HOME%\server\default\deploy\%SERVER_XML%
if exist "%JBOSS_HOME%\server\default\deploy\tomcat41-service.xml" copy tmp\%SERVER_XML% %JBOSS_HOME%\server\default\deploy\%SERVER_XML%
if exist "%JBOSS_HOME%\server\default\deploy\jbossweb.sar\META-INF\jboss-service.xml" copy tmp\%SERVER_XML% %JBOSS_HOME%\server\default\deploy\jbossweb.sar\META-INF\jboss-service.xml
if exist "%JBOSS_HOME%\server\default\deploy\jbossweb-jetty.sar\META-INF\jboss-service.xml" copy tmp\%SERVER_XML% %JBOSS_HOME%\server\default\deploy\jbossweb-jetty.sar\META-INF\jboss-service.xml

del tmp\%SERVER_XML%

goto end
:error
echo Usage: setup-adminweb <CA Name> <DN Server Cert> <keystore passwd> <SuperAdmin password> <java cacert keystore passwd> 
:end
