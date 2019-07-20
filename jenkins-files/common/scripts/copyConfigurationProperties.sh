#!/bin/sh

# copyConfigurationProperties.sh SRC_PATH TARGET_PATH DB_CONTAINER JDK DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                                [1]      [2]         [3]          [4] [5]       [6]        [7]           [8]

########################################################################################################################
# database.properties variables
########################################################################################################################
DATASOURCE_JNDI_NAME="EjbcaDS"
DATABASE_NAME=""
DATABASE_URL=""
DATABASE_DRIVER=""
DATABASE_USERNAME=""
DATABASE_PASSWORD=""

########################################################################################################################
# ejbca.properties variables
########################################################################################################################
APPSERVER_HOME=""
APPSERVER_TYPE=""

# Copy resources in alphabetical order

echo "Copying cesecore.properties (without filtering)..."
cp $1/cesecore.properties $2/

echo "Copying cmptcp.properties (without filtering)..."
cp $1/cmptcp.properties $2/

echo "Copying database.properties (with filtering)..."
if [ $5 = "db2" ]
then
    echo "Using DB2 pattern..."
    DATABASE_NAME="db2"
    DATABASE_URL="jdbc:db2://${3}:50000/ejbca"
    DATABASE_DRIVER="com.ibm.db2.jcc.DB2Driver"
    DATABASE_USERNAME="db2inst1"
    DATABASE_PASSWORD="db2inst1"
elif [ $5 = "mariadb" ]
then
    echo "Using MariaDB pattern..."
    DATABASE_NAME="mysql"
    DATABASE_URL="jdbc:mysql://${3}:3306/ejbca"
    DATABASE_DRIVER="org.mariadb.jdbc.Driver"
    DATABASE_USERNAME="ejbca"
    DATABASE_PASSWORD="ejbca"
elif [ $5 = "mssql" ]
then
    echo "Using MS SQL pattern..."
    DATABASE_NAME="mssql"
    DATABASE_URL="jdbc:sqlserver://${3}:1433;databaseName=ejbca"
    DATABASE_DRIVER="com.microsoft.sqlserver.jdbc.SQLServerDriver"
    DATABASE_USERNAME="sa"
    DATABASE_PASSWORD="MyEjbcaPass1100"
elif [ $5 = "oracle" ]
then
    echo "Using Oracle DB pattern..."
    DATABASE_NAME="oracle"
    DATABASE_URL="jdbc:oracle:${3}:@oracledb:1521:XE"
    DATABASE_DRIVER="oracle.jdbc.driver.OracleDriver"
    DATABASE_USERNAME="ejbca"
    DATABASE_PASSWORD="ejbca"
else
  echo "Error: Cannot map the database family"
  exit 1
fi
sed -e "s#DATASOURCE_JNDI_NAME#$DATASOURCE_JNDI_NAME#" \
    -e "s#DATABASE_NAME#$DATABASE_NAME#" \
    -e "s#DATABASE_URL#$DATABASE_URL#" \
    -e "s#DATABASE_DRIVER#$DATABASE_DRIVER#" \
    -e "s#DATABASE_USERNAME#$DATABASE_USERNAME#" \
    -e "s#DATABASE_PASSWORD#$DATABASE_PASSWORD#" \
    $1/database.properties > $2/database.properties

echo "Copying databaseprotection.properties (without filtering)..."
cp $1/databaseprotection.properties $2/

echo "Copying ejbca.properties (with filtering)..."
if [ $7 = "wildfly" ]
then
    echo "Using WildFly pattern..."
    APPSERVER_HOME="/opt/jboss/wildfly"
    APPSERVER_TYPE="jboss"
else
  echo "Error: Cannot map the application server family"
  exit 1
fi
sed -e "s#APPSERVER_HOME#$APPSERVER_HOME#" \
    -e "s#APPSERVER_TYPE#$APPSERVER_TYPE#" \
    $1/ejbca.properties > $2/ejbca.properties

echo "Copying install.properties (without filtering)..."
cp $1/install.properties $2/