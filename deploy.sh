#!/bin/sh
#-x

if [ -f $JBOSS_HOME ]
then
	echo JBOSS_HOME must be set to deploy automgically.
	exit
fi

cp dist/*.war $JBOSS_HOME/deploy
cp dist/*.jar $JBOSS_HOME/deploy

echo bcprov.jar must be copied to jboss/lib/ext.
