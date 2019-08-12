#!/bin/sh

# copyConfigurationProperties.sh SRC_PATH TARGET_PATH DB_CONTAINER JDK DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                                [1]      [2]         [3]          [4] [5]       [6]        [7]           [8]

########################################################################################################################
# database.properties replacement variables
########################################################################################################################
#DATASOURCE_JNDI_NAME
#DATABASE_NAME
#DATABASE_URL
#DATABASE_DRIVER
#DATABASE_USERNAME
#DATABASE_PASSWORD

########################################################################################################################
# ejbca.properties replacement variables
########################################################################################################################
#APPSERVER_HOME
APPSERVER_HOME=""
#APPSERVER_TYPE
APPSERVER_TYPE=""

########################################################################################################################
# jndi.properties.jboss
########################################################################################################################
COPY_JNDI_PROPERTIES_JBOSS=false

########################################################################################################################
# Setup variables
########################################################################################################################
# Call setDatabaseConnectionVariables.sh to reuse database connection variables
$2/setDatabaseConnectionVariables.sh $1 $2 $3 $4 $5 $6 $7 $8

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
sed -e "s#DATASOURCE_JNDI_NAME#$DB_DATASOURCE_JNDI_NAME#" \
    -e "s#DATABASE_NAME#$DB_NAME#" \
    -e "s#DATABASE_URL#$DB_DATASOURCE_CONNECTION_URL#" \
    -e "s#DATABASE_DRIVER#$DB_DRIVER#" \
    -e "s#DATABASE_USERNAME#$DB_DATASOURCE_USERNAME#" \
    -e "s#DATABASE_PASSWORD#$DB_DATASOURCE_PASSWORD#" \
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
