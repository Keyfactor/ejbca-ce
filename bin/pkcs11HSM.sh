#!/bin/bash

# 
# Create a key via a PKCS#11 device # 
# Example:
#

if [ -z $EJBCA_HOME ]; then
	echo "Fatal error: EJBCA_HOME is not set"
	exit 1
fi

if [ -z $JAVA_HOME ]; then
	echo "Fatal error: JAVA_HOME is not set"
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
$JAVA_HOME/bin/java -cp $CLASSES org.ejbca.ui.cli.HSMKeyTool $args
