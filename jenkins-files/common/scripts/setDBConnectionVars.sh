#!/bin/sh

# This utility script defines the database connection variables and exports them.
# setDBConnectionVars.sh JENKINS_FILES_DB BUILD_FOLDER_DB DOCKER_NAME_DB JDK_VERSION DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                        [1]              [2]             [3]            [4]         [5]       [6]        [7]           [8]
#echo
#echo "setDBConnectionVars.sh [$1] [$2] [$3] [$4] [$5] [$6] [$7] [$8]"
#echo

########################################################################################################################
# Variables
########################################################################################################################
DB_NAME=""
DB_DRIVER=""
DB_DATASOURCE_JNDI_NAME="EjbcaDS"
DB_DATASOURCE_CONNECTION_URL=""
DB_DATASOURCE_DRIVER=""
DB_DATASOURCE_DRIVER_CLASS=""
DB_DATASOURCE_USERNAME=""
DB_DATASOURCE_PASSWORD=""
DB_DATASOURCE_VALID_CONNECTION_SQL=""
DB_DATASOURCE_VALID_CONNECTION_CHECKER=""
DB_DRIVER_NAME=""
DB_DRIVER_MODULE=""
DB_DRIVER_XA_CLASS=""
DB_DRIVER_DRIVER_CLASS=""

########################################################################################################################
# Setup variables
########################################################################################################################
if [ $5 = "db2" ]
then
    DB_NAME="db2"
    DB_DRIVER="com.ibm.db2.jcc.DB2Driver"
    DB_DATASOURCE_CONNECTION_URL="jdbc:db2://$3:50000/ejbca"
    DB_DATASOURCE_DRIVER="db2"
    DB_DATASOURCE_DRIVER_CLASS=""
    DB_DATASOURCE_USERNAME="db2inst1"
    DB_DATASOURCE_PASSWORD="db2inst1"
    DB_DATASOURCE_VALID_CONNECTION_SQL="select 1 from sysibm.sysdummy1"
    DB_DATASOURCE_VALID_CONNECTION_CHECKER=""
    DB_DRIVER_NAME="db2"
    DB_DRIVER_MODULE="com.ibm.db2"
    DB_DRIVER_XA_CLASS="com.ibm.db2.jcc.DB2XADataSource"
    DB_DRIVER_DRIVER_CLASS=""
elif [ $5 = "mariadb" ]
then
    DB_NAME="mysql"
    DB_DRIVER="org.mariadb.jdbc.Driver"
    DB_DATASOURCE_CONNECTION_URL="jdbc:mysql://$3:3306/ejbca"
    DB_DATASOURCE_DRIVER="dbdriver.jar"
    DB_DATASOURCE_DRIVER_CLASS="org.mariadb.jdbc.Driver"
    DB_DATASOURCE_USERNAME="ejbca"
    DB_DATASOURCE_PASSWORD="ejbca"
    DB_DATASOURCE_VALID_CONNECTION_SQL="select 1;"
    DB_DATASOURCE_VALID_CONNECTION_CHECKER=""
    DB_DRIVER_NAME=""
    DB_DRIVER_MODULE=""
    DB_DRIVER_XA_CLASS=""
    DB_DRIVER_DRIVER_CLASS=""
elif [ $5 = "mssql" ]
then
    DB_NAME="mssql"
    DB_DRIVER="com.microsoft.sqlserver.jdbc.SQLServerDriver"
    DB_DATASOURCE_CONNECTION_URL="jdbc:sqlserver://$3:1433;databaseName=ejbca"
    DB_DATASOURCE_DRIVER="mssql"
    DB_DATASOURCE_DRIVER_CLASS=""
    DB_DATASOURCE_USERNAME="sa"
    DB_DATASOURCE_PASSWORD="MyEjbcaPass1100"
    DB_DATASOURCE_VALID_CONNECTION_SQL=""
    DB_DATASOURCE_VALID_CONNECTION_CHECKER="org.jboss.jca.adapters.jdbc.extensions.mssql.MSSQLValidConnectionChecker"
    DB_DRIVER_NAME="mssql"
    DB_DRIVER_MODULE="com.microsoft.mssql"
    DB_DRIVER_XA_CLASS=""
    DB_DRIVER_DRIVER_CLASS="com.microsoft.sqlserver.jdbc.SQLServerDriver"
elif [ $5 = "oracle" ]
then
    DB_NAME="oracle"
    DB_DRIVER="oracle.jdbc.driver.OracleDriver"
    DB_DATASOURCE_CONNECTION_URL="jdbc:oracle:${3}:@oracledb:1521:XE"
    DB_DATASOURCE_DRIVER=""
    DB_DATASOURCE_DRIVER_CLASS=""
    DB_DATASOURCE_USERNAME=""
    DB_DATASOURCE_PASSWORD=""
    DB_DATASOURCE_VALID_CONNECTION_SQL=""
    DB_DATASOURCE_VALID_CONNECTION_CHECKER=""
    DB_DRIVER_NAME=""
    DB_DRIVER_MODULE=""
    DB_DRIVER_XA_CLASS=""
    DB_DRIVER_DRIVER_CLASS=""
    echo "Error: Not implemented"
    exit 1
else
  echo "Error: Cannot map the database family"
  exit 1
fi

########################################################################################################################
# Export variables
########################################################################################################################
export DB_NAME="$DB_NAME"
export DB_DRIVER="$DB_DRIVER"
export DB_DATASOURCE_JNDI_NAME="$DB_DATASOURCE_JNDI_NAME"
export DB_DATASOURCE_CONNECTION_URL="$DB_DATASOURCE_CONNECTION_URL"
export DB_DATASOURCE_DRIVER="$DB_DATASOURCE_DRIVER"
export DB_DATASOURCE_DRIVER_CLASS="$DB_DATASOURCE_DRIVER_CLASS"
export DB_DATASOURCE_USERNAME="$DB_DATASOURCE_USERNAME"
export DB_DATASOURCE_PASSWORD="$DB_DATASOURCE_PASSWORD"
export DB_DATASOURCE_VALID_CONNECTION_SQL="$DB_DATASOURCE_VALID_CONNECTION_SQL"
export DB_DATASOURCE_VALID_CONNECTION_CHECKER="$DB_DATASOURCE_VALID_CONNECTION_CHECKER"
export DB_DRIVER_NAME="$DB_DRIVER_NAME"
export DB_DRIVER_MODULE="$DB_DRIVER_MODULE"
export DB_DRIVER_XA_CLASS="$DB_DRIVER_XA_CLASS"
export DB_DRIVER_DRIVER_CLASS="$DB_DRIVER_DRIVER_CLASS"
