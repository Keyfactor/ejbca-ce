#!/usr/bin/env bash

JAVACMD=$(which java)
# Check that JAVA_HOME is set
if [ -z "$JAVA_HOME" ]; then
    if [ -z "$JAVACMD" ]
    then
        echo "You must set JAVA_HOME before running the EJBCA Batch Enrollment GUI." 1>&2
        exit 1
    fi
else
    JAVACMD=$JAVA_HOME/bin/java
fi

if [ -z "$EJBCA_HOME" ] ; then
	EJBCA_FILE="$0" 
    EJBCA_HOME="$(dirname "$(dirname "$EJBCA_FILE")")"
fi

OLD_PWD=$(pwd)
cd "$EJBCA_HOME/modules/batchenrollment-gui" || exit 1
exec "$JAVACMD" -jar -Dlog4j1.compatibility=true "$EJBCA_HOME"/modules/batchenrollment-gui/dist/batchenrollment-gui.jar "$@"
cd "$OLD_PWD" || exit 0

