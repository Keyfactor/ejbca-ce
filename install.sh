#!/bin/sh
IFS=


JAVACACERTPASSWD=$1
if [ -f $1 ]
then
    
    JAVACACERTPASSWD=changeit    
fi

# Check for proper settings of environment variables
if [ -f $JBOSS_HOME ]
then
        echo JBOSS_HOME must be set in order to install sucessfully.
        exit
fi
if [ -f $JAVA_HOME ]
then
        echo JAVA_HOME must be set in order to install sucessfully.
        exit
fi

if java -version 
then    echo    
else    echo java must be set in the PATH in order to execute install successfully.
        exit
fi


if [ ! -x ./ca.sh ]
then
        echo ca.sh, setup-adminweb.sh and setup.sh must have executive bit set.
        exit
fi

if [ ! -x ./setup.sh ]
then
        echo ca.sh, setup-adminweb.sh and setup.sh must have executive bit set.
        exit
fi

if [ ! -x ./setup-adminweb.sh ]
then
        echo ca.sh, setup-adminweb.sh and setup.sh must have executive bit set.
        exit
fi



CP=.:./admin.jar:./lib/ldap.jar:$JBOSS_HOME/client/jnp-client.jar:$JBOSS_HOME/client/jboss-j2ee.jar:$JBOSS_HOME/client/jbossall-client.jar:$JBOSS_HOME/client/jboss-client.jar:$JBOSS_HOME/client/jbosssx-client.jar:$JBOSS_HOME/client/jboss-common-client.jar

if java -cp $CP se.anatom.ejbca.admin.Install install unix en ejbca jboss
then
#This command must be run as root
echo
echo Importing certs in the JAVA trust store requires root privileges
echo Enter the root password when prompted:
if ! eval 'su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -delete -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $JAVACACERTPASSWD"'
then echo su failed. Please try again.
  if ! eval 'su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -delete -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $JAVACACERTPASSWD"'
  then echo su failed. Please try again.
    if ! eval 'su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -delete -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $JAVACACERTPASSWD"'
    then echo Installation failed. Exiting...
         exit    
    fi
  fi
fi
echo and again...

if ! eval 'su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -import -trustcacerts -file tmp/rootca.der -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $JAVACACERTPASSWD"'
then echo su failed. Please try again.
  if ! eval 'su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -import -trustcacerts -file tmp/rootca.der -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $JAVACACERTPASSWD"'
  then echo su failed. Please try again.
    if ! eval 'su -c "$JAVA_HOME/bin/keytool -alias EJBCA-CA -import -trustcacerts -file tmp/rootca.der -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass $JAVACACERTPASSWD"'
    then echo Installation failed. Exiting...
         exit    
    fi
  fi
fi
rm tmp/rootca.der

java -cp $CP se.anatom.ejbca.admin.Install displayendmessage unix en ejbca jboss
fi 

