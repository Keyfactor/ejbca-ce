#!/bin/sh
#-x

KEYSTORE=src/ca/ca/keyStore/server.p12

# Check for proper settings of environment variables
if [ -f $JBOSS_HOME ]
then
        echo JBOSS_HOME must be set to deploy automagically.
        exit
fi

# Install keystore is 'keystore' is given as argument to deploy
if [ $1 ]
then
    if (( $1==keystore )) 
    then
        if ! [ -f $JBOSS_HOME/server/default/conf/server.p12 ]
        then
            cp $KEYSTORE $JBOSS_HOME/server/default/conf
            echo Copied $KEYSTORE to $JBOSS_HOME/server/default/conf.
        else
            echo $JBOSS_HOME/server/default/conf/server.p12 already exist, no files copied.
        fi
    fi
fi

# Install BouncyCastle provider and ldap.jar
if ! [ -f $JBOSS_HOME/lib/jce-jdk13-112.jar ]
then
  cp lib/jce-jdk13-112.jar $JBOSS_HOME/lib
  echo Copied jce-jdk13-112.jar to $JBOSS_HOME/lib. JBoss must be restared.
fi
if ! [ -f $JBOSS_HOME/lib/ldap.jar ]
then
  cp lib/ldap.jar $JBOSS_HOME/lib
  echo Copied ldap.jar to $JBOSS_HOME/lib. JBoss must be restared.
fi

# Deploy jar and war files
cp dist/ejbca-ca.ear $JBOSS_HOME/server/default/deploy
cp dist/ra.jar $JBOSS_HOME/server/default/deploy
echo Deployed jar- and war-files in $JBOSS_HOME/server/default/deploy

