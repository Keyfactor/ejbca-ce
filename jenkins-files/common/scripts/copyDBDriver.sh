#!/bin/sh

# This utility script defines the database driver and copies it.
# copyDBDriver.sh JENKINS_FILES_LIB BUILD_FOLDER DOCKER_NAME_DB JDK_VERSION DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                 [1]               [2]          [3]            [4]         [5]       [6]        [7]           [8]
#echo
#echo "copyDBDriver.sh [$1] [$2] [$3] [$4] [$5] [$6] [$7] [$8]"
#echo

MODULE_XML=""
MODULE_JAR=""

########################################################################################################################
# Setup variables
########################################################################################################################
if [ $5 = "db2" ]
then
    MODULE_XML="module_$4.xml"
    MODULE_JAR="db2jcc4.jar"
elif [ $5 = "mariadb" ]
then
    MODULE_JAR="mariadb-java-client.jar"
elif [ $5 = "mssql" ]
then
    MODULE_XML="module_$4.xml"
    MODULE_JAR="mssql-jdbc-7.2.2.jre$4.jar"
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
