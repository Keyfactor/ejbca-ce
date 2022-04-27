#!/usr/bin/env bash

JAVACMD=$(which java)

if [ -z "$JAVACMD" ]; then
    if [ -z "$JAVA_HOME" ]; then
        echo 'You must set JAVA_HOME before running the EJBCA CLI.' 1>&2
        exit 1
    else
	    JAVACMD="$JAVA_HOME/bin/java"
    fi
fi


if [ -z "$EJBCA_HOME" ]; then
    # It is important to set EJBCA_HOME since some code in the JAR use this variable
    EJBCA_HOME=$(dirname "$0")/../
fi

CLI_JAR="$EJBCA_HOME/dist/ejbca-ejb-cli/ejbca-ejb-cli.jar"

if [ ! -f "$CLI_JAR" ]; then
    echo "Cannot find the EJBCA CLI binary '$CLI_JAR'." 1>&2
    exit 2
fi

exec "$JAVACMD" -Dlog4j1.compatibility=true -jar "$CLI_JAR" "$@"
