#!/bin/sh
IFS=


JAVACACERTPASSWD=$1
if [ -f $1 ]
then
    
    JAVACACERTPASSWD=changeit    
fi


CP=.:./admin.jar:./lib/ldap.jar

java -cp $CP se.anatom.ejbca.admin.Install install unix en ejbca jboss tomcat



#This command must be run as root
echo
echo Importing certs in the JAVA trust store requires root privileges
echo Enter the root password when prompted:
su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -delete -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $JAVACACERTPASSWD"
echo and again...
su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -import -trustcacerts -file tmp/rootca.der -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $JAVACACERTPASSWD"

rm tmp/rootca.der

java -cp $CP se.anatom.ejbca.admin.Install displayendmessage unix en ejbca jboss tomcat


