#!/bin/sh
#-x

if [ -f $JBOSS_HOME ]
then
        echo JBOSS_HOME must be set to deploy automagically.
        exit
fi

cp dist/*.war $JBOSS_HOME/deploy
cp dist/*.jar $JBOSS_HOME/deploy
echo Deployed jar- and war-files in $JBOSS_HOME/deploy

if ! [ -f $JBOSS_HOME/lib/ext/jce-jdk13-111.jar ]
then
  cp lib/jce-jdk13-111.jar $JBOSS_HOME/lib/ext
  echo Copied jce-jdk13-111.jar to $JBOSS_HOME/lib/ext. JBoss must be restared.
fi
if ! [ -f $JBOSS_HOME/lib/ext/ldap.jar ]
then
  cp lib/ldap.jar $JBOSS_HOME/lib/ext
  echo Copied ldap.jar to $JBOSS_HOME/lib/ext. JBoss must be restared.
fi

