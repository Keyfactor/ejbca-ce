#!/bin/sh
IFS=

# This script sets up the administrative web interface with client cert authentication.
# Usage: setup-adminweb <CA Name> <DN Server Cert> <keystore passwd> <SuperAdmin password> <java cacert keystore passwd>

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

cp p12/tomcat.jks $JBOSS_HOME/bin/tomcat.jks

./ca.sh getrootcert $1 tmp/rootca.der -der

#This command must be run as root
echo
echo Importing certs in the JAVA trust store requires root privileges
echo Enter the root password when prompted:
su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -delete -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $5"
echo and again...
su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -import -trustcacerts -file tmp/rootca.der -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $5"

rm tmp/rootca.der

export CP=.:./admin.jar

# JBoss 3.0.x
if [ -f $JBOSS_HOME/server/default/deploy/tomcat4-service.xml ]
then
	SERVER_XML=tomcat4-service.xml
elif [ -f $JBOSS_HOME/server/default/deploy/tomcat41-service.xml ]
then
	SERVER_XML=tomcat41-service.xml
elif [ -f $JBOSS_HOME/server/default/deploy/jbossweb.sar/META-INF/jboss-service.xml ]
then
	SERVER_XML=jetty.xml
# JBoss 3.2.0
elif [ -f $JBOSS_HOME/server/default/deploy/jbossweb-jetty.sar/META-INF/jboss-service.xml ]
then
	SERVER_XML=jetty32.xml
# JBoss 3.2.2/3.2.3
elif [ -f $JBOSS_HOME/server/default/deploy/jbossweb-tomcat41.sar/META-INF/jboss-service.xml ]
then
	SERVER_XML=tomcat41-jboss32.xml
else
    echo !!!!!
    echo Unhandled version of JBoss, SSL support must be set up manually
    echo !!!!!
fi

java -cp $CP se.anatom.ejbca.util.TomcatServiceXMLPasswordReplace src/adminweb/WEB-INF/$SERVER_XML tmp/$SERVER_XML $3

if [ -f $JBOSS_HOME/server/default/deploy/tomcat4-service.xml ]
then
	cp tmp/$SERVER_XML $JBOSS_HOME/server/default/deploy/$SERVER_XML
elif [ -f $JBOSS_HOME/server/default/deploy/tomcat41-service.xml ]
then
	cp tmp/$SERVER_XML $JBOSS_HOME/server/default/deploy/$SERVER_XML
elif [ -f $JBOSS_HOME/server/default/deploy/jbossweb.sar/META-INF/jboss-service.xml ]
then
	cp tmp/$SERVER_XML $JBOSS_HOME/server/default/deploy/jbossweb.sar/META-INF/jboss-service.xml
elif [ -f $JBOSS_HOME/server/default/deploy/jbossweb-jetty.sar/META-INF/jboss-service.xml ]
then
	cp tmp/$SERVER_XML $JBOSS_HOME/server/default/deploy/jbossweb-jetty.sar/META-INF/jboss-service.xml
elif [ -f $JBOSS_HOME/server/default/deploy/jbossweb-tomcat41.sar/META-INF/jboss-service.xml ]
then
	cp tmp/$SERVER_XML $JBOSS_HOME/server/default/deploy/jbossweb-tomcat41.sar/META-INF/jboss-service.xml
else
    echo !!!!!
    echo Unhandled version of JBoss, SSL support must be set up manually
    echo !!!!!
fi

if [ -f tmp/$SERVER_XML ]
then 
	rm tmp/$SERVER_XML
fi

