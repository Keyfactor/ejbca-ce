#!/bin/sh

# copyConfigurationProperties.sh TARGET_PATH DB_CONTAINER JDK DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                                [1]         [2]          [3] [4]       [5]        [6]           [7]
echo "TARGET_PATH: $1"
echo "DB_HOST: $2"
echo "JDK: $3"
echo "DB_FAMILY: $4"
echo "DB_VERSION: $5"
echo "SERVER_FAMILY: $6"
echo "SERVER_VERSION: $7"

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
cp ../conf/cesecore.properties $1/

echo "Copying cmptcp.properties (without filtering)..."
cp ../conf/cmptcp.properties $1/

echo "Copying database.properties (with filtering)..."
if   [[ $4 == "db2" ]]; then
    DATABASE_NAME= "db2"
    DATABASE_URL="jdbc:db2://${2}:50000/ejbca"
    DATABASE_DRIVER="com.ibm.db2.jcc.DB2Driver"
    DATABASE_USERNAME="db2inst1"
    DATABASE_PASSWORD="db2inst1"
elif [[ $4 == "mariadb" ]]; then
    DATABASE_NAME= "mysql"
    DATABASE_URL="jdbc:mysql://${2}:3306/ejbca"
    DATABASE_DRIVER="org.mariadb.jdbc.Driver"
    DATABASE_USERNAME="ejbca"
    DATABASE_PASSWORD="ejbca"
elif [[ $4 == "mssql" ]]; then
    DATABASE_NAME= "mssql"
    DATABASE_URL="jdbc:sqlserver://${2}:1433;databaseName=ejbca"
    DATABASE_DRIVER="com.microsoft.sqlserver.jdbc.SQLServerDriver"
    DATABASE_USERNAME="sa"
    DATABASE_PASSWORD="MyEjbcaPass1100"
elif [[ $4 == "oracle" ]]; then
    DATABASE_NAME= "oracle"
    DATABASE_URL="jdbc:oracle:${2}:@oracledb:1521:XE"
    DATABASE_DRIVER="oracle.jdbc.driver.OracleDriver"
    DATABASE_USERNAME="ejbca"
    DATABASE_PASSWORD="ejbca"
else
  echo "Error: Cannot map the datbase family"
  exit 1
fi

cp ../conf/database.properties $1/
sed -e "s/\${DATABASE_NAME}/${DATABASE_NAME}/" -e "s/\${DATABASE_URL}/${DATABASE_URL}/" $1/database.properties