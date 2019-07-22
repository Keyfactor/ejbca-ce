#!/bin/sh

# copyDatabaseDriver.sh SRC_PATH TARGET_PATH DB_CONTAINER JDK DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                       [1]      [2]         [3]          [4] [5]       [6]        [7]           [8]

MODULE_XML=""
MODULE_JAR=""

if [ $5 = "db2" ]
then
    echo "Using DB2 library..."
    MODULE_XML="module_$4.xml"
    MODULE_JAR="db2jcc4.jar"
elif [ $5 = "mariadb" ]
then
    echo "Using MariaDB library..."
    MODULE_JAR="mariadb-java-client.jar"
elif [ $5 = "mssql" ]
then
    echo "Using MS SQL library..."
    MODULE_XML="module_$4.xml"
    MODULE_JAR="mssql-jdbc-7.2.2.jre$4.jar"
elif [ $5 = "oracle" ]
then
    echo "Using Oracle library..."
    echo "Error: Not implemented"
    exit 1
else
  echo "Error: Cannot map the database family"
  exit 1
fi

if [ "x$MODULE_XML" != "x" ]
then
    cp $1/$5/$MODULE_XML $2/module.xml
else
    echo "" > $2/module.xml
fi

if [ "x$MODULE_JAR" != "x" ]
then
    cp $1/$5/$MODULE_JAR $2/dbdriver.jar
fi
