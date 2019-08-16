#!/bin/sh

# This utility script defines the database docker artifacts and copies them.
# copyDBDocker.sh JENKINS_FILES_DB BUILD_FOLDER_DB DOCKER_NAME_DB JDK_VERSION DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                 [1]              [2]             [3]            [4]         [5]       [6]        [7]           [8]
#echo
#echo "copyDBDocker.sh [$1] [$2] [$3] [$4] [$5] [$6] [$7] [$8]"
#echo

########################################################################################################################
# Variables
########################################################################################################################
DOCKERFILE_PATH=""
DOCKERFILE_INIT_SCRIPT_PATH=""

########################################################################################################################
# Setup variables
########################################################################################################################
if [ $5 = "db2" ]
then
    if [ -f "$1/$5/$6/Dockerfile" ]
    then
        DOCKERFILE_PATH="$1/$5/$6/Dockerfile"
        DOCKERFILE_INIT_SCRIPT_PATH="$1/$5/$6/db2_init_ejbca.sh"
    else
        echo "Error: Cannot find the DB2 container with version $6"
        exit 1
    fi
elif [ $5 = "mariadb" ]
then
    if [ -f "$1/$5/$6/Dockerfile" ]
    then
        DOCKERFILE_PATH="$1/$5/$6/Dockerfile"
        DOCKERFILE_INIT_SCRIPT_PATH=""
    else
        echo "Error: Cannot find the MariaDB container with version $6"
        exit 1
    fi
elif [ $5 = "mssql" ]
then
    if [ -f "$1/$5/$6/Dockerfile" ]
    then
        DOCKERFILE_PATH="$1/$5/$6/Dockerfile"
        DOCKERFILE_INIT_SCRIPT_PATH="$1/$5/$6/entrypoint.sh"
    else
        echo "Error: Cannot find the MSSQL container with version $6"
        exit 1
    fi

elif [ $5 = "oracle" ]
then
    echo "Error: Not implemented"
    exit 1
else
  echo "Error: Cannot map the database family"
  exit 1
fi

########################################################################################################################
# Copy resources
########################################################################################################################
cp $DOCKERFILE_PATH $2/

if [ "x${DOCKERFILE_INIT_SCRIPT_PATH}" != "x" ]
then
    cp $DOCKERFILE_INIT_SCRIPT_PATH $2/
fi
