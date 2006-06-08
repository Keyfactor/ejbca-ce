#!/usr/bin/env bash

"$JAVA_HOME/bin/java" -cp $EJBCA_HOME/lib/LunaJCASP.jar:$EJBCA_HOME/tmp/bin/classes org.ejbca.ui.cli.LunaKeyTool "$@"
