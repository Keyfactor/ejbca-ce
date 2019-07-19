#!/bin/sh

# copyConfigurationProperties.sh SRC_PATH TARGET_PATH DB_CONTAINER JDK DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                                [1]      [2]         [3]          [4] [5]       [6]        [7]           [8]
echo "SRC_PATH: $1"
echo "TARGET_PATH: $2"
echo "DB_HOST: $3"
echo "JDK: $4"
echo "DB_FAMILY: $5"
echo "DB_VERSION: $6"
echo "SERVER_FAMILY: $7"
echo "SERVER_VERSION: $8"

########################################################################################################################
# database.properties variables
########################################################################################################################
DATASOURCE_JNDI_NAME="EjbcaDS"
# db2
# mysql
# mssql
# oracle
DATABASE_NAME=""
# jdbc:db2://db_ee_cos7_openjdk8_wf10_nohsm_db2:50000/ejbca
# jdbc:mysql://mariadb_1:3306/ejbca
# jdbc:sqlserver://db_ee_cos7_openjdk8_wf10_nohsm_mssql2017:1433;databaseName=ejbca
# jdbc:oracle:thin:@oracledb:1521:XE
DATABASE_URL=""
# com.ibm.db2.jcc.DB2Driver
# org.mariadb.jdbc.Driver
# com.microsoft.sqlserver.jdbc.SQLServerDriver
# oracle.jdbc.driver.OracleDriver
DATABASE_DRIVER=""
# db2inst1
# ejbca
# sa
# ejbca
DATABASE_USERNAME=""
# db2inst1
# ejbca
# MyEjbcaPass1100
# ejbca
DATABASE_PASSWORD=""

########################################################################################################################
# ejbca.properties variables
########################################################################################################################
# /opt/jboss/wildfly
APPSERVER_HOME=""
# jboss
APPSERVER_TYPE=""

echo "Copying cesecore.properties (without filtering)..."
cp $1/cesecore.properties $2/

echo "Copying cmptcp.properties (without filtering)..."
cp $1/cmptcp.properties $2/

echo "Copying database.properties (with filtering)..."
if [ $5 == "db2" ]; then
    echo "Using DB2 pattern..."
    DATABASE_NAME="db2"
    DATABASE_URL="jdbc:db2://${3}:50000/ejbca"
    DATABASE_DRIVER="com.ibm.db2.jcc.DB2Driver"
    DATABASE_USERNAME="db2inst1"
    DATABASE_PASSWORD="db2inst1"
elif [ $5 == "mariadb" ]; then
    echo "Using MariaDB pattern..."
    DATABASE_NAME="mysql"
    DATABASE_URL="jdbc:mysql://${3}:3306/ejbca"
    DATABASE_DRIVER="org.mariadb.jdbc.Driver"
    DATABASE_USERNAME="ejbca"
    DATABASE_PASSWORD="ejbca"
elif [ $5 == "mssql" ]; then
    echo "Using MS SQL pattern..."
    DATABASE_NAME="mssql"
    DATABASE_URL="jdbc:sqlserver://${3}:1433;databaseName=ejbca"
    DATABASE_DRIVER="com.microsoft.sqlserver.jdbc.SQLServerDriver"
    DATABASE_USERNAME="sa"
    DATABASE_PASSWORD="MyEjbcaPass1100"
elif [ $5 == "oracle" ]; then
    echo "Using Oracle DB pattern..."
    DATABASE_NAME="oracle"
    DATABASE_URL="jdbc:oracle:${3}:@oracledb:1521:XE"
    DATABASE_DRIVER="oracle.jdbc.driver.OracleDriver"
    DATABASE_USERNAME="ejbca"
    DATABASE_PASSWORD="ejbca"
else
  echo "Error: Cannot map the datbase family"
  exit 1
fi

cp $1/database.properties $2/
sed -e "s/\${DATABASE_NAME}/${DATABASE_NAME}/" -e "s/\${DATABASE_URL}/${DATABASE_URL}/" $2/database.properties