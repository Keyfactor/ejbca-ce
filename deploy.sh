#!/bin/sh
#-x

KEYSTORE=src/ca/keyStore/server.p12

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
        if ! [ -f $JBOSS_HOME/conf/server.p12 ]
        then
            cp $KEYSTORE $JBOSS_HOME/conf
            echo Copied $KEYSTORE to $JBOSS_HOME/conf.
        else
            echo $KEYSTORE already exist, no files copied.
        fi
    fi
fi

# Install BouncyCastle provider and ldap.jar
if ! [ -f $JBOSS_HOME/lib/ext/jce-jdk13-112.jar ]
then
  cp lib/jce-jdk13-112.jar $JBOSS_HOME/lib/ext
  echo Copied jce-jdk13-112.jar to $JBOSS_HOME/lib/ext. JBoss must be restared.
fi
if ! [ -f $JBOSS_HOME/lib/ext/ldap.jar ]
then
  cp lib/ldap.jar $JBOSS_HOME/lib/ext
  echo Copied ldap.jar to $JBOSS_HOME/lib/ext. JBoss must be restared.
fi

# Deploy jar and war files
cp dist/*.war $JBOSS_HOME/deploy
cp dist/*.jar $JBOSS_HOME/deploy
echo Deployed jar- and war-files in $JBOSS_HOME/deploy
