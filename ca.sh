#!/bin/sh

java -cp  .:./admin.jar:./lib/jnp-client.jar:./lib/jboss-client.jar:./lib/jboss-jaas.jar:./lib/log4j.jar:./lib/jce-jdk13-111.jar se.anatom.ejbca.admin.ca $1 $2 $3 $4 $5 $6 $7 $8
