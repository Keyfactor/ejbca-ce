#!/bin/sh
IFS=

# This script sets up the administrative web interface with client cert authentication.
# Usage: setup-adminweb <DN Tomcat Server Cert> <Tomcat keystore passwd> <java cacert keystore passwd>

if [ -f $1 ]
then
	goto error
fi
if [ -f $2 ]
then
	goto error
fi

ra.sh adduser tomcat $2 $1 null null 1 3

ra.sh adduser walter foo123 "CN=walter" null null 65 2

ra.sh setclearpwd tomcat $2

ra.sh setclearpwd walter foo123

batch.sh

cp p12/tomcat.jks $JBOSS_HOME/.keystore

ca.sh getrootcert tmp/rootca.der

keytool -import -trustcacerts -file tmp\rootca.der -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $3

rm tmp/rootca.der

export CP=.:./admin.jar:./lib/regexp1_0_0.jar

java -cp $CP se.anatom.ejbca.util.TomcatServiceXMLPasswordReplace src/adminweb/WEB-INF/tomcat4-service.xml tmp/tomcat4-service.xml %2

cp tmp/tomcat4-service.xml $JBOSS_HOME/server/default/deploy/tomcat4-service.xml

rm tmp/tomcat4-service.xml

goto end
:error
echo "Usage: setup-adminweb <DN Tomcat Server Cert> <Tomcat keystore passwd> <java cacert keystore passwd>"
:end
