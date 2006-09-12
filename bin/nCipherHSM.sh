#!/bin/bash

args="$0 $1 "
shift
args+="com.ncipher.provider.km.nCipherKM nCipher.sworld "
args+="$@"
JARS=/opt/nfast/java/classes
cp=$JARS/rsaprivenc.jar:$JARS/nfjava.jar:$JARS/kmjava.jar:$JARS/kmcsp.jar:$JARS/jutils.jar
cp+=:$EJBCA_HOME/lib/bcprov-jdk15.jar
#cp+=:$EJBCA_HOME/out/classes
cp+=:$EJBCA_HOME/tmp/bin/classes

"$JAVA_HOME/bin/java" -cp $cp org.ejbca.ui.cli.HSMKeyTool $args
