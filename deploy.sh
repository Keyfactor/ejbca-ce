#!/bin/sh
#-x

if [ -f $JBOSS_HOME ]
then
        echo JBOSS_HOME must be set to deploy automagically.
        exit
fi

cp dist/*.war $JBOSS_HOME/deploy
cp dist/*.jar $JBOSS_HOME/deploy

cp lib/jce-jdk13-111.jar $JBOSS_HOME/lib/ext
cp lib/ldap.jar $JBOSS_HOME/lib/ext

#echo jce-jdk13-111.jar and ldap.jar  must be placed in jboss/lib/ext.
