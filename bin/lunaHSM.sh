#!/usr/bin/env bash

if [ -z $EJBCA_HOME ]; then
        echo "Fatal error: EJBCA_HOME is not set"
        exit 1
fi

if [ -z $JAVA_HOME ]; then
        echo "Fatal error: JAVA_HOME is not set"
fi

"$JAVA_HOME/bin/java" -cp $EJBCA_HOME/lib/LunaJCASP.jar:$EJBCA_HOME/tmp/bin/classes org.ejbca.ui.cli.LunaKeyTool "$@"
