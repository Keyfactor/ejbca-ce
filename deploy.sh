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
if ! [ -f $JBOSS_HOME/server/default/lib/jce-jdk13-115.jar ]
then
  cp lib/jce-jdk13-115.jar $JBOSS_HOME/server/default/lib
  echo Copied jce-jdk13-115.jar to $JBOSS_HOME/server/default/lib. JBoss must be restared.
fi
if ! [ -f $JBOSS_HOME/server/default/lib/ldap.jar ]
then
  cp lib/ldap.jar $JBOSS_HOME/server/default/lib
  echo Copied ldap.jar to $JBOSS_HOME/server/default/lib. JBoss must be restared.
fi
if ! [ -f $JBOSS_HOME/server/default/lib/regexp1_0_0.jar ]
then
  cp lib/regexp1_0_0.jar $JBOSS_HOME/server/default/lib
  echo Copied regexp1_0_0.jar to $JBOSS_HOME/server/default/lib. JBoss must be restared.
fi


# Deploy jar and war files
CAEARSRC=dist/ejbca-ca.ear
if [ $1 ]
then
    if (( $1==nora )) 
    then
      CAEARSRC=dist/ejbca-canora.ear
    fi
fi
echo Copying $CAEARSRC...
cp $CAEARSRC $JBOSS_HOME/server/default/deploy/ejbca-ca.ear
# cp dist/ra.jar $JBOSS_HOME/server/default/deploy
# cp dist/raadmin.war $JBOSS_HOME/server/default/deploy
echo Deployed jar- and war-files in $JBOSS_HOME/server/default/deploy

