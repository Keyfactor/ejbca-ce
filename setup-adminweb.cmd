@echo off
rem This script sets up the administrative web interface with client cert authentication.
rem Usage: setup-adminweb <DN Tomcat Server Cert> <Tomcat keystore passwd> <java cacert keystore passwd>

call ra adduser tomcat %2 %1 "" null 1 3

call ra adduser walter foo123 "CN=walter" "" null 65 2

call ra setclearpwd tomcat %2

call ra setclearpwd walter foo123

call batch

copy p12\tomcat.jks %JBOSS_HOME%\.keystore

call ca getrootcert tmp\rootca.der

keytool -import -trustcacerts -file tmp\rootca.der -keystore %JAVA_HOME%\jre\lib\security\cacerts -storepass %3

del tmp\rootca.der

set CP=.;.\admin.jar;.\lib\regexp1_0_0.jar

java -cp %CP% se.anatom.ejbca.util.TomcatServiceXMLPasswordReplace src\adminweb\WEB-INF\tomcat4-service.xml tmp\tomcat4-service.xml %2

copy tmp\tomcat4-service.xml %JBOSS_HOME%\server\default\deploy\tomcat4-service.xml

del tmp\tomcat4-service.xml
