@echo off

rem JBoss
set CP=.;.\admin.jar;.\lib\jnp-client.jar;.\lib\jboss-client.jar;.\lib\jboss-j2ee.jar;.\lib\jbosssx-client.jar;.\lib\jboss-common-client.jar;.\lib\junit.jar;.\lib\log4j-1.2.jar;.\lib\jce-jdk13-114.jar

rem Weblogic
rem set CP=.;.\admin.jar;.\lib\weblogic.jar;.\lib\junit.jar;.\lib\log4j-1.2.jar;.\lib\jce-jdk13-114.jar

rem JBoss
java -cp %CP% se.anatom.ejbca.admin.ca %1 %2 %3 %4 %5 %6 %7 %8

rem Weblogic
rem java %CP% se.anatom.ejbca.admin.ca %1 %2 %3 %4 %5 %6 %7 %8
