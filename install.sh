#!/bin/sh
IFS=



CP=.:./admin.jar:./lib/ldap.jar

java -cp $CP se.anatom.ejbca.admin.Install unix en ejbca jboss jetty

