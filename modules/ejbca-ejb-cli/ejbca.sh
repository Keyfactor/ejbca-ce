#!/usr/bin/env bash

JAVACMD=`which java`
# Check that JAVA_HOME is set
if [ ! -n "$JAVA_HOME" ]; then
    if [ ! -n "$JAVACMD" ]
    then
        echo "You must set JAVA_HOME before running the EJBCA EJB CLI." 1>&2
        exit 1
    fi
else
    JAVACMD=$JAVA_HOME/bin/java
fi

exec "$JAVACMD" -Dlog4j1.compatibility=true -jar ejbca-ejb-cli.jar "$@"
