#!/bin/sh
IFS=

# JBoss
CP=.:./admin.jar:./lib/jnp-client.jar:./lib/jboss-j2ee.jar:./lib/jboss-client.jar:./lib/jbosssx-client.jar:./lib/jboss-common-client.jar:./lib/junit.jar:./lib/log4j-1.2.jar:./lib/jce-jdk13-114.jar

# Weblogic
#CP=.:./admin.jar:./lib/weblogic.jar:./lib/junit.jar:./lib/log4j-1.2.jar:./lib/jce-jdk13-114.jar

# JBoss
java -cp $CP se.anatom.ejbca.admin.ra $1 $2 $3 $4 $5 $6 $7 $8

# Weblogic
#java -cp $CP se.anatom.ejbca.admin.ra $1 $2 $3 $4 $5 $6 $7 $8
