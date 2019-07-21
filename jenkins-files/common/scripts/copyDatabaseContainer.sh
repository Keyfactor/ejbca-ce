#!/bin/sh

# copyDatabaseContainer.sh SRC_PATH TARGET_PATH DB_CONTAINER JDK DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                          [1]      [2]         [3]          [4] [5]       [6]        [7]           [8]

DOCKERFILE_PATH=""
DOCKERFILE_INIT_SCRIPT_PATH=""

if [ $5 = "db2" ]
then
    echo "Using DB2 container..."
    if [ -f "$1/$5/$6/Dockerfile" ]
    then
        echo "Found DB2 container with version $6"
        DOCKERFILE_PATH="$1/$5/$6/Dockerfile"
        DOCKERFILE_INIT_SCRIPT_PATH="$1/$5/$6/db2_init_ejbca.sh"
    else
        echo "Error: Cannot find the DB2 container with version $6"
        exit 1
    fi
elif [ $5 = "mariadb" ]
then
    echo "Using MariaDB container..."
    if [ -f "$1/$5/$6/Dockerfile" ]
    then
        echo "Found MariaDB container with version $6"
        DOCKERFILE_PATH="$1/$5/$6/Dockerfile"
    else
        echo "Error: Cannot find the MariaDB container with version $6"
        exit 1
    fi
elif [ $5 = "mssql" ]
then
    echo "Using MS SQL container..."
    echo "Error: Not implemented"
    exit 1
elif [ $5 = "oracle" ]
then
    echo "Using Oracle container..."
    echo "Error: Not implemented"
    exit 1
else
  echo "Error: Cannot map the database family"
  exit 1
fi

# Copy resources
cp $DOCKERFILE_PATH $2/

if [ "x$DOCKERFILE_INIT_SCRIPT_PATH" != "x" ]
then
    cp $DOCKERFILE_INIT_SCRIPT_PATH $2/
fi