#!/bin/sh

# JBoss
java -cp ./:./admin.jar:./lib/jnp-client.jar:./lib/jboss-client.jar:./lib/jboss-jaas.jar:./lib/log4j.jar:./lib/jce-jdk13-112.jar se.anatom.ejbca.batch.BatchMakeP12 $1 $2

# Weblogic
#java -cp ./:./admin.jar:./lib/weblogic.jar:./lib/log4j.jar:./lib/jce-jdk13-112.jar se.anatom.ejbca.batch.BatchMakeP12 $1 $2