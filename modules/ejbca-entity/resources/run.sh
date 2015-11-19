#!/bin/sh

# Memory settings can be specified using parameters like: JAVA_OPT="-Xms20480m -Xmx20480m -XX:MaxPermSize=384m" run.sh ....
java ${JAVA_OPT} -server -XX:+UseConcMarkSweepGC -XX:+ExplicitGCInvokesConcurrent -XX:-UseGCOverheadLimit -Djava.endorsed.dirs=`dirname "$0"`/endorsed -jar `dirname "$0"`/ejbca-db-cli.jar "$@"

ERRORLEVEL="$?"
if [ "x${ERRORLEVEL}" = "x1" ] ; then
	echo "If you see errors while running the CLI similar to \"JDBC Driver class not found\" your should copy your JDBC driver JAR to `dirname "$0"`/endorsed"
fi

exit ${ERRORLEVEL}
