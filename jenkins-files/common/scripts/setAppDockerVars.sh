#!/bin/sh

# This utility script defines application server docker runtime variables and exports them.
# setAppDockerVars.sh JENKINS_FILES_SERVER BUILD_FOLDER DOCKER_NAME_APP JDK_VERSION DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION EJBCA
#                     [1]                  [2]          [3]             [4]         [5]       [6]        [7]           [8]            [9]
#echo
#echo "setAppDockerVars.sh [$1] [$2] [$3] [$4] [$5] [$6] [$7] [$8] [$9]"
#echo

########################################################################################################################
# Variables
########################################################################################################################
DOCKER_APP_EXTRA_ARGS=""
DOCKER_APP_VOLUME_ARGS=""

########################################################################################################################
# Setup variables
########################################################################################################################
if [ $7 = "wildfly" ]
then
    # EJB RPC 4447
    # common port 8080
    # unprivileged 8442
    # privileged 8443
    # management 9990
    DOCKER_APP_EXTRA_ARGS="-p 4447:4447 -p 8080:8080 -p 8442:8442 -p 8443:8443 -p 9990:9990"
    DOCKER_APP_VOLUME_ARGS="-v ${2}:/app -v ${9}:/app/ejbca -v ${2}/deployments:/opt/jboss/wildfly/standalone/deployments/:rw"
else
    echo "Error: Cannot map the application server family"
    exit 1
fi

########################################################################################################################
# Export variables
########################################################################################################################
export DOCKER_APP_EXTRA_ARGS="${DOCKER_APP_EXTRA_ARGS}"
export DOCKER_APP_VOLUME_ARGS="${DOCKER_APP_VOLUME_ARGS}"
