#!/bin/sh

java -cp ./:./admin.jar:./lib/jnp-client.jar:./lib/jboss-client.jar:./lib/jboss-jaas.jar:./lib/log4j.jar:./lib/jce-jdk13-111.jar se.anatom.ejbca.batch.BatchMakeP12 $1
