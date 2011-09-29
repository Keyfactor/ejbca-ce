#!/bin/sh

java -Djava.endorsed.dirs=`dirname "$0"`/endorsed -jar `dirname "$0"`/ejbca-db-cli.jar "$@"

ERRORLEVEL="$?"
if [ "x${ERRORLEVEL}" = "x1" ] ; then
	echo "If you see errors while running the CLI similar to \"JDBC Driver class not found\" your should copy your JDBC driver JAR to `dirname "$0"`/endorsed"
fi
