#!/bin/sh

java -cp ./:./admin.jar:./lib/jnp-client.jar:./lib/jboss-client.jar:./lib/jboss-jaas.jar:./lib/log4j.jar:./lib/bcprov.jar se.anatom.ejbca.admin.ra $1 $2 $3 $4 $5 $6

