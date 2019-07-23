#!/bin/sh

# setDatabaseContainerEnvVarExtraArgs.sh SRC_PATH TARGET_PATH DB_CONTAINER JDK DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                                        [1]      [2]         [3]          [4] [5]       [6]        [7]           [8]

DOCKERFILE_EXTRA_ARGS=""

########################################################################################################################
# Setup variables
########################################################################################################################
if [ $5 = "db2" ]
then
    DOCKERFILE_EXTRA_ARGS="--privileged=true -p 50000:50000"
elif [ $5 = "mariadb" ]
then
    # -p 3306:3306
    DOCKERFILE_EXTRA_ARGS=" "
elif [ $5 = "mssql" ]
then
    DOCKERFILE_EXTRA_ARGS="-p 1433:1433"
elif [ $5 = "oracle" ]
then
    exit 1
else
  exit 1
fi

########################################################################################################################
# Output result
########################################################################################################################
echo $DOCKERFILE_EXTRA_ARGS