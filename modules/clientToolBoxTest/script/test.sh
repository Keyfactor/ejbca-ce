#!/bin/bash

disthome=$(dirname ${0})
jarTest=${disthome}/clientToolBoxTest.jar

if [[ "${jarClient}" == "" ]] ; then
	jarClient=./clientToolBox/clientToolBox.jar
fi
cp ${disthome}/log4j.xml $(dirname ${jarClient})/properties

java -cp ${jarClient}:${jarTest} org.ejbca.ui.cli.clientToolBoxTest.start.Main "$@"
if (( $? != 0 )); then echo "Test failed."; exit -1; fi
