#!/bin/sh

# This utility script defines the database docker runtime variables and exports them.
# setDBDockerVars.sh JENKINS_FILES_DB BUILD_FOLDER_DB DOCKER_NAME_DB JDK_VERSION DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                    [1]              [2]             [3]            [4]         [5]       [6]        [7]           [8]
#echo
#echo "setDBDockerVars.sh [$1] [$2] [$3] [$4] [$5] [$6] [$7] [$8]"
#echo

########################################################################################################################
# Variables
########################################################################################################################
DOCKER_DB_EXTRA_ARGS=""
DOCKER_DB_VOLUME_ARGS=""
DOCKER_DB_VOLUME_PATH=""
DB_DRIVER_MODULE_PATH=""

########################################################################################################################
# Setup variables
########################################################################################################################
if [ $5 = "db2" ]
then
    DOCKER_DB_EXTRA_ARGS="--privileged=true -i -p 50000:50000"
    DOCKER_DB_VOLUME_ARGS="-v $2:/database"
    DOCKER_DB_VOLUME_PATH="x"
    DB_DRIVER_MODULE_PATH="com/ibm/db2/main/"
elif [ $5 = "mariadb" ]
then
    # -p 3306:3306
    DOCKER_DB_EXTRA_ARGS="-i -p 3306:3306"
    DOCKER_DB_VOLUME_ARGS="-v $2/mysql:/var/lib/mysql"
    DOCKER_DB_VOLUME_PATH="mysql"
    DB_DRIVER_MODULE_PATH="x"
elif [ $5 = "mssql" ]
then
    DOCKER_DB_EXTRA_ARGS="-i -p 1433:1433"
    DOCKER_DB_VOLUME_ARGS=""
    DOCKER_DB_VOLUME_PATH="x"
    DB_DRIVER_MODULE_PATH="com/microsoft/mssql/main/"
elif [ $5 = "oracle" ]
then
    DOCKER_DB_EXTRA_ARGS="-i"
    DOCKER_DB_VOLUME_ARGS=""
    DOCKER_DB_VOLUME_PATH="x"
    DB_DRIVER_MODULE_PATH="x"
    echo "Error: Not implemented"
    exit 1
else
    exit 1
fi

########################################################################################################################
# Export variables
########################################################################################################################
export DOCKER_DB_EXTRA_ARGS="${DOCKER_DB_EXTRA_ARGS}"
export DOCKER_DB_VOLUME_ARGS="${DOCKER_DB_VOLUME_ARGS}"
export DOCKER_DB_VOLUME_PATH="${DOCKER_DB_VOLUME_PATH}"
export DB_DRIVER_MODULE_PATH="${DB_DRIVER_MODULE_PATH}"
