#!/bin/sh
IFS=

# This script sets up the administrative web interface with client cert authentication.
# Usage: setup-adminweb <CA Name> <DN Server Cert> <keystore passwd> <java cacert keystore passwd>

if [ -f $1 ]
then
    echo "Usage: setup-adminweb <CA Name> <DN Server Cert> <keystore passwd> <SuperAdmin password> <java cacert keystore passwd>"
    exit
fi
if [ -f $2 ]
then
    echo "Usage: setup-adminweb <CA Name> <DN Server Cert> <keystore passwd> <SuperAdmin password> <java cacert keystore passwd>"
    exit
fi
if [ -f $3 ]
then
    echo "Usage: setup-adminweb <CA Name> <DN Server Cert> <keystore passwd> <SuperAdmin password> <java cacert keystore passwd>"
    exit
fi
if [ -f $4 ]
then
    echo "Usage: setup-adminweb <CA Name> <DN Server Cert> <keystore passwd> <SuperAdmin password> <java cacert keystore passwd>"
    exit
fi

if [ -f $5 ]
then
    echo "Usage: setup-adminweb <CA Name> <DN Server Cert> <keystore passwd> <SuperAdmin password> <java cacert keystore passwd>"
    exit
fi


./ra.sh adduser tomcat $3 $2 null $1 null 1 3

./ra.sh adduser superadmin $4 "CN=SuperAdmin" null $1 null 65 2

./ra.sh setclearpwd tomcat $3

./ra.sh setclearpwd superadmin $4

./batch.sh

cp p12/tomcat.jks $JBOSS_HOME/bin/.keystore

./ca.sh getrootcert $1 tmp/rootca.der

#This command must be run as root
echo
echo Importing certs in the JAVA trust store requires root privileges
echo Enter the root password when prompted:
su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -delete -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $5"
echo and again...
su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -import -trustcacerts -file tmp/rootca.der -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $5"

rm tmp/rootca.der

export CP=.:./admin.jar

if [ -f $JBOSS_HOME/server/default/deploy/tomcat4-service.xml ]
then
	SERVER_XML=tomcat4-service.xml
elif [ -f $JBOSS_HOME/server/default/deploy/tomcat41-service.xml ]
then
	SERVER_XML=tomcat41-service.xml
elif [ -f $JBOSS_HOME/server/default/deploy/jbossweb.sar/META-INF/jboss-service.xml ]
then
	SERVER_XML=jetty.xml
elif [ -f $JBOSS_HOME/server/default/deploy/jbossweb-jetty.sar/META-INF/jboss-service.xml ]
then
	SERVER_XML=jetty32.xml
fi

java -cp $CP se.anatom.ejbca.util.TomcatServiceXMLPasswordReplace src/adminweb/WEB-INF/$SERVER_XML tmp/$SERVER_XML $3

if [ -f $JBOSS_HOME/server/default/deploy/jbossweb.sar/META-INF/jboss-service.xml ]
then
	cp tmp/$SERVER_XML $JBOSS_HOME/server/default/deploy/jbossweb.sar/META-INF/jboss-service.xml
elif [ -f $JBOSS_HOME/server/default/deploy/jbossweb-jetty.sar/META-INF/jboss-service.xml ]
then
	cp tmp/$SERVER_XML $JBOSS_HOME/server/default/deploy/jbossweb-jetty.sar/META-INF/jboss-service.xml
else
	cp tmp/$SERVER_XML $JBOSS_HOME/server/default/deploy/$SERVER_XML
fi

if [ -f tmp/$SERVER_XML ]
then 
	rm tmp/$SERVER_XML
fi
