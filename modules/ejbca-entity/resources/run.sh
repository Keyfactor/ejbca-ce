#!/bin/sh

# Manual classpath to include all JDBC drivers we put in 'endorsed'
export MYCP=`dirname "$0"`/ejbca-db-cli.jar:`dirname "$0"`/endorsed/*
#echo $MYCP 

# Memory settings can be specified using parameters like: JAVA_OPT="-Xms20480m -Xmx20480m -XX:MaxPermSize=384m" run.sh ....
if [ "x${JAVA_OPT}" = "x" ] ; then
    echo
else
    echo Using JAVA_OPT: ${JAVA_OPT}
fi
java ${JAVA_OPT} -cp $MYCP org.ejbca.database.DatabaseCli "$@"

ERRORLEVEL="$?"
if [ "x${ERRORLEVEL}" = "x1" ] ; then
	echo "If you see errors while running the CLI similar to \"JDBC Driver class not found\" your should copy your JDBC driver JAR to `dirname "$0"`/endorsed"
fi

exit ${ERRORLEVEL}
