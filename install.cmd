@echo off

set CP=.;.\admin.jar;.\lib\ldap.jar

java -cp %CP% se.anatom.ejbca.admin.Install windows en ejbca jboss jetty

