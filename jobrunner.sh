#!/bin/sh

java -cp ./:./admin.jar:./lib/jnp-client.jar:./lib/jboss-client.jar:./lib/jboss-jaas.jar:./lib/log4j.jar:./lib/jce-jdk13-111b.jar se.anatom.ejbca.util.JobRunner $1 $2 $3 $4
