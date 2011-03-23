#!/usr/bin/env bash

JAVACMD=`which java`
# Check that JAVA_HOME is set
if [ ! -n "$JAVA_HOME" ]; then
    if [ ! -n "$JAVACMD" ]
    then
        echo "You must set JAVA_HOME before running the EJBCA cli." 1>&2
        exit 1
    fi
else
    JAVACMD=$JAVA_HOME/bin/java
fi

if [ -z "$EJBCA_HOME" ] ; then
	EJBCA_FILE="$0" 
	EJBCA_HOME=`echo $(dirname $EJBCA_FILE)`
	cd $EJBCA_HOME
	cd ..
	EJBCA_HOME=`pwd`
fi

exec "$JAVACMD" -jar $EJBCA_HOME/dist/ejbca-ejb-cli/ejbca-ejb-cli.jar "$@"
