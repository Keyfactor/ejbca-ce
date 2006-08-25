#!/bin/bash

args="$0 $1 "
shift
shift
args+="com.ncipher.provider.km.nCipherKM nCipher.sworld "
args+="$*"

export cp=/opt/nfast/java/classes/rsaprivenc.jar:/opt/nfast/java/classes/nfjava.jar:/opt/nfast/java/classes/kmjava.jar:/opt/nfast/java/classes/kmcsp.jar:/opt/nfast/java/classes/jutils.jar:$EJBCA_HOME/tmp/bin/classes

echo "$JAVA_HOME/bin/java" -cp $cp org.ejbca.ui.cli.KeyTool $args
