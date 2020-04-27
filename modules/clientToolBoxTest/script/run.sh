#!/bin/bash

disthome=$(dirname ${0})

if (( $# < 1 )); then
	echo "Do '$0 noTest' just to run the docker images."
	${disthome}/test.sh
	exit 0
fi

hostsFile="/etc/hosts"
hostsFileOrig="/etc/hosts.noDocker"

if [ ! -w ${hostsFile} ] ; then
	echo "Write permission must be granted to the file ${hostsFile}."
	exit -1
fi
if [ ! -r ${hostsFileOrig} ] ; then
	echo "The file ${hostsFileOrig} must exist and read permission must be granted to it."
	echo "Copy ${hostsFile} to ${hostsFileOrig} before running this script for the first time."
	exit -1
fi

if [[ "x${ca_name}" == "x" ]] ; then
	ca_name=ca
	if [[ "x${ca_image}" == "x" ]] ; then
		ca_image=ca
	fi

	docker rm -f ${ca_name} 2>/dev/null

	#args="-v /:/home/jboss/hostRoot:ro ${args}"
	args="-tid ${args}"
	if [[ "x${command}" == "x" ]] ; then
		command="/root/start-jboss"
	fi

	docker run --name ${ca_name} -h ca ${args} ${ca_image} ${command}
	if (( $? != 0 )); then echo "Not possible to create docker CA container"; exit -1; fi
else
	docker start ${args} ${ca_name}
	if (( $? != 0 )); then echo "Not possible to start a docker CA container"; exit -1; fi
fi

ca_ip=$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' ${ca_name})
if (( $? != 0 )); then echo "Not possible to get CA IP."; exit -1; fi

cp ${hostsFileOrig} ${hostsFile}
if (( $? != 0 )); then exit $?; fi
echo "${ca_ip}	ca" >> ${hostsFile}
if (( $? != 0 )); then exit $?; fi

n=0
until wget http://ca:8080/ejbca/ejbcaws/ejbcaws?wsdl -O /dev/null 2>/dev/null; do
	if (( n++>100 )); then
		echo "WS not working, the CA is probably not started"
		exit -1:
	fi
	sleep 1
	echo "waited ${n} seconds for start of WS"
done

if [[ "$1" == "noTest" ]]; then echo "No test. You may now configure the CA"; exit 0; fi

${disthome}/test.sh "$@"
if (( $? != 0 )); then exit $?; fi

docker rm -f ${ca_name}
cp ${hostsFileOrig} ${hostsFile}
