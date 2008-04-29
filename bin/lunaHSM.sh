#!/bin/sh

JAVACMD=`which java`
# Check that JAVA_HOME is set
if [ ! -n "$JAVA_HOME" ]; then
    if [ ! -n "$JAVACMD" ]
    then
        echo "You must set JAVA_HOME before running the EJBCA cli."
        exit 1
    fi
else
    JAVACMD=$JAVA_HOME/bin/java
fi

if [ -z $EJBCA_HOME ]; then
        echo "Environment variable EJBCA_HOME must be set"
        exit 1
fi

"$JAVACMD" -cp $EJBCA_HOME/lib/LunaJCASP.jar:$EJBCA_HOME/tmp/bin/classes org.ejbca.ui.cli.LunaKeyTool "$@"
