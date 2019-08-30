#!/bin/sh

JAVACMD="$(which java)"
# Check that JAVA_HOME is set
if [ -z "$JAVA_HOME" ]; then
    if [ -z "$JAVACMD" ]; then
        echo "You must set JAVA_HOME before running the P11Ng CLI." 1>&2
        exit 1
    fi
else
    JAVACMD="$JAVA_HOME/bin/java"
fi

# ConfigDump is often packaged separately from EJBCA, so we can't locate it through EJBCA_HOME
if [ -z "$P11NGCLI_HOME" ]; then
    P11NGCLI_HOME="$(dirname "$0")"
    if [ -z "$P11NGCLI_HOME" ]; then
        # Fallback
        P11NGCLI_HOME=.
    fi
fi

exec "$JAVACMD" -jar "$P11NGCLI_HOME/p11ngcli.jar" "$@"
