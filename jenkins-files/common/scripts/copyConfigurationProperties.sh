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

########################################################################################################################
# jndi.properties.jboss
########################################################################################################################
COPY_JNDI_PROPERTIES_JBOSS=false

########################################################################################################################
# Setup variables
########################################################################################################################
# Database
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
# Application server
if [ $7 = "wildfly" ]
then
    echo "Using WildFly pattern..."
    APPSERVER_HOME="/opt/jboss/wildfly"
    APPSERVER_TYPE="jboss"
    if [ $8 = "14.0.0.Final" ]
    then
        COPY_JNDI_PROPERTIES_JBOSS=true
    fi
else
  echo "Error: Cannot map the application server family"
  exit 1
fi

########################################################################################################################
# Copy resources in alphabetical order
########################################################################################################################
echo "Copying cesecore.properties (without filtering)..."
cp $1/cesecore.properties $2/

echo "Copying cmptcp.properties (without filtering)..."
cp $1/cmptcp.properties $2/

echo "Copying database.properties (with filtering)..."
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
sed -e "s#APPSERVER_HOME#$APPSERVER_HOME#" \
    -e "s#APPSERVER_TYPE#$APPSERVER_TYPE#" \
    $1/ejbca.properties > $2/ejbca.properties

echo "Copying install.properties (without filtering)..."
cp $1/install.properties $2/

if [ "xCOPY_JNDI_PROPERTIES_JBOSS" != "x" ]
then
    echo "Copying jndi.properties.jboss (without filtering)..."
    cp $1/jndi.properties.jboss $2/
fi
