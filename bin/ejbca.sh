#!/usr/bin/env bash

JAVACMD=$(which java)

if [ ! -n "$JAVACMD" ]; then
    if [ ! -n "$JAVA_HOME" ]; then
        echo 'You must set JAVA_HOME before running the EJBCA CLI.' 1>&2
        exit 1
    else
	JAVACMD="$JAVA_HOME/bin/java"
    fi
fi


if [ ! -n "$EJBCA_HOME" ]; then
    CLI_JAR=$(dirname "$0")/../dist/ejbca-ejb-cli/ejbca-ejb-cli.jar
else
    CLI_JAR="$EJBCA_HOME/dist/ejbca-ejb-cli/ejbca-ejb-cli.jar"
fi

if [ ! -f "$CLI_JAR" ]; then
    echo "Cannot find the EJBCA CLI binary '$CLI_JAR'." 1>&2
    exit 2
fi

"$JAVACMD" -jar "$CLI_JAR" "$@"
