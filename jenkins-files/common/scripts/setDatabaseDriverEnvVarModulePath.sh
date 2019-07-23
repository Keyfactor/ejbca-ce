#!/bin/sh

# setDatabaseDriverEnvVarModulePath.sh SRC_PATH TARGET_PATH DB_CONTAINER JDK DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                                      [1]      [2]         [3]          [4] [5]       [6]        [7]           [8]

DB_DRIVER_MODULE_PATH=""

########################################################################################################################
# Setup variables
########################################################################################################################
if [ $5 = "db2" ]
then
    DB_DRIVER_MODULE_PATH="com/ibm/db2/main/"
elif [ $5 = "mariadb" ]
then
    DB_DRIVER_MODULE_PATH="x"
elif [ $5 = "mssql" ]
then
    DB_DRIVER_MODULE_PATH="com/microsoft/mssql/main/"
elif [ $5 = "oracle" ]
then
    DB_DRIVER_MODULE_PATH=""
else
  exit 1
fi

########################################################################################################################
# Output result
########################################################################################################################
echo $DB_DRIVER_MODULE_PATH