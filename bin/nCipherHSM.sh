#!/bin/bash

args="$0 $1 "
shift
args+="com.ncipher.provider.km.nCipherKM nCipher.sworld "
args+="$@"

cp=/opt/nfast/java/classes/rsaprivenc.jar:/opt/nfast/java/classes/nfjava.jar:/opt/nfast/java/classes/kmjava.jar:/opt/nfast/java/classes/kmcsp.jar:/opt/nfast/java/classes/jcetools.jar:/opt/nfast/java/classes/jutils.jar
cp+=:$EJBCA_HOME/out/classes
#cp+=:$EJBCA_HOME/tmp/bin/classes

"$JAVA_HOME/bin/java" -cp $cp org.ejbca.ui.cli.KeyTool $args
