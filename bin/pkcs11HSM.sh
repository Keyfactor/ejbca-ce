#!/bin/bash

# 
# Create a key via a PKCS#11 device # 
# Example:
#

if [ -z "$EJBCA_HOME" ] ; then
	EJBCA_FILE="$0" 
	EJBCA_HOME=`echo $(dirname $(dirname $EJBCA_FILE))`
fi

#if [ -z $EJBCA_HOME ]; then
#	echo "Fatal error: EJBCA_HOME is not set"
#	exit 1
#fi

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

CLASSES=$EJBCA_HOME/lib/bcprov-jdk15.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/bcmail-jdk15.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/log4j.jar
CLASSES=$CLASSES:$EJBCA_HOME/lib/commons-lang-2.0.jar
CLASSES=$CLASSES:$EJBCA_HOME/tmp/bin/classes
# use this instead if you want build from eclipse
#CLASSES=$CLASSES:$EJBCA_HOME/out/classes

# Prepare arguments
if [ -z $1 ]; then
  args="`basename $0` dummy dummy"
else
  #command name
  args="`basename $0` $1"
  shift
  if [ -z $1 ]; then
  	args="$args dummy"
  else
    #shared library name
    args="$args $1"
    shift
  fi
fi
args="$args null pkcs11 $@"

# Finally run java
#set -x
$JAVACMD -cp $CLASSES org.ejbca.ui.cli.HSMKeyTool $args
