#!/bin/sh

# copyDatabaseContainer.sh SRC_PATH TARGET_PATH DB_CONTAINER JDK DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                          [1]      [2]         [3]          [4] [5]       [6]        [7]           [8]

DOCKERFILE_PATH=""
DOCKERFILE_RUN_PATH=""
DOCKERFILE_ENV_PATH=""
DOCKERFILE_STANDALONE_FILTERED=false
DOCKERFILE_STANDALONE1_PATH=""
DOCKERFILE_STANDALONE2_PATH=""
DB_DOCKERFILE_DATASOURCE_JNDI_NAME="java:/EjbcaDS"          # Export
DB_DOCKERFILE_DATASOURCE_CONNECTION_URL=""                  # Export
DB_DOCKERFILE_DATASOURCE_DRIVER=""                          # Export
DB_DOCKERFILE_DATASOURCE_DRIVER_CLASS=""                    # Export
DOCKERFILE_STANDALONE_DATASOURCE_DRIVER_CLASS_TAG=""
DB_DOCKERFILE_DATASOURCE_USERNAME=""                        # Export
DB_DOCKERFILE_DATASOURCE_PASSWORD=""                        # Export
DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_SQL=""            # Export
DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_CHECKER=""        # Export
DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG=""
DB_DOCKERFILE_DRIVER_NAME=""                                # Export
DB_DOCKERFILE_DRIVER_MODULE=""                              # Export
DB_DOCKERFILE_DRIVER_XA_CLASS=""                            # Export
DB_DOCKERFILE_DRIVER_DRIVER_CLASS=""                        # Export
DOCKERFILE_STANDALONE_DRIVER_TAG=""

########################################################################################################################
# Setup variables
########################################################################################################################
echo "Looking for application server container..."
if [ $7 = "wildfly" ]
then
    if [ -f "$1/$7/$8/Dockerfile" ]
    then
        echo "Found WildFly container with version $8"
        DOCKERFILE_PATH="$1/$7/$8/Dockerfile"
        DOCKERFILE_RUN_PATH="$1/$7/$8/run.sh"
        DOCKERFILE_ENV_PATH="$1/$7/$8/env.sh"
        if [ -f "$1/$7/$8/standalone1.xml" ]
        then
            DOCKERFILE_STANDALONE_FILTERED=true
            DOCKERFILE_STANDALONE1_PATH="$1/$7/$8/standalone1.xml"
            DOCKERFILE_STANDALONE2_PATH="$1/$7/$8/standalone2.xml"
        else
            DOCKERFILE_STANDALONE_FILTERED=false
            DOCKERFILE_STANDALONE1_PATH=""
            DOCKERFILE_STANDALONE2_PATH=""
        fi
    else
        echo "Error: Cannot find the WildFly container with version $6"
        exit 1
    fi
else
  echo "Error: Cannot map the application server family"
  exit 1
fi

echo "Configuring database variables..."
if [ $5 = "db2" ]
then
    echo "Using DB2 pattern..."
    DB_DOCKERFILE_DATASOURCE_CONNECTION_URL="jdbc:db2://$3:50000/ejbca"
    DB_DOCKERFILE_DATASOURCE_DRIVER="db2"
    DB_DOCKERFILE_DATASOURCE_DRIVER_CLASS=""
    DB_DOCKERFILE_DATASOURCE_USERNAME="db2inst1"
    DB_DOCKERFILE_DATASOURCE_PASSWORD="db2inst1"
    DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_SQL="select 1 from sysibm.sysdummy1"
    DB_DOCKERFILE_DRIVER_NAME="db2"
    DB_DOCKERFILE_DRIVER_MODULE="com.ibm.db2"
    DB_DOCKERFILE_DRIVER_XA_CLASS="com.ibm.db2.jcc.DB2XADataSource"
    DB_DOCKERFILE_DRIVER_DRIVER_CLASS=""
elif [ $5 = "mariadb" ]
then
    echo "Using MariaDB pattern..."
    DB_DOCKERFILE_DATASOURCE_CONNECTION_URL="jdbc:mysql://$3:3306/ejbca"
    DB_DOCKERFILE_DATASOURCE_DRIVER="dbdriver.jar"
    DB_DOCKERFILE_DATASOURCE_DRIVER_CLASS="org.mariadb.jdbc.Driver"
    DB_DOCKERFILE_DATASOURCE_USERNAME="ejbca"
    DB_DOCKERFILE_DATASOURCE_PASSWORD="ejbca"
    DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_SQL="select 1;"
    DB_DOCKERFILE_DRIVER_NAME=""
elif [ $5 = "mssql" ]
then
    echo "Using MS SQL pattern..."
    DB_DOCKERFILE_DATASOURCE_CONNECTION_URL="jdbc:sqlserver://$3:1433;databaseName=ejbca"
    DB_DOCKERFILE_DATASOURCE_DRIVER="mssql"
    DB_DOCKERFILE_DATASOURCE_DRIVER_CLASS=""
    DB_DOCKERFILE_DATASOURCE_USERNAME="sa"
    DB_DOCKERFILE_DATASOURCE_PASSWORD="MyEjbcaPass1100"
    DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_CHECKER="org.jboss.jca.adapters.jdbc.extensions.mssql.MSSQLValidConnectionChecker"
    DB_DOCKERFILE_DRIVER_NAME="mssql"
    DB_DOCKERFILE_DRIVER_MODULE="com.microsoft.mssql"
    DB_DOCKERFILE_DRIVER_XA_CLASS=""
    DB_DOCKERFILE_DRIVER_DRIVER_CLASS="com.microsoft.sqlserver.jdbc.SQLServerDriver"
elif [ $5 = "oracle" ]
then
    echo "Using Oracle DB pattern..."
    echo "Error: Not implemented"
    exit 1
else
  echo "Error: Cannot map the database family"
  exit 1
fi

########################################################################################################################
# Copy resources
########################################################################################################################
cp $DOCKERFILE_PATH $2/
cp $DOCKERFILE_RUN_PATH $2/
cp $DOCKERFILE_ENV_PATH $2/

if [ $DOCKERFILE_STANDALONE_FILTERED = true ]
then
    echo "Configuring database in standalone.xml files..."
    # Wrap driver-class if any
    if [ "x$DB_DOCKERFILE_DATASOURCE_DRIVER_CLASS" != "x" ]
    then
        DOCKERFILE_STANDALONE_DATASOURCE_DRIVER_CLASS_TAG="<driver-class>$DB_DOCKERFILE_DATASOURCE_DRIVER_CLASS</driver-class>"
    fi
    # Wrap valid connection sql
    if[ "x$DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_SQL" != "x" ]
    then
        DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG="<check-valid-connection-sql>$DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_SQL</check-valid-connection-sql>"
    fi
    # Wrap valid connection checker class
    if[ "x$DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_CHECKER" != "x" ]
    then
        DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG="<valid-connection-checker class-name=\"$DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_CHECKER\"/>"
    fi
    # Wrap
    if[ "x$DB_DOCKERFILE_DRIVER_NAME" != "x" ]
    then
        DOCKERFILE_STANDALONE_DRIVER_INTERNAL_TAG=""
        if[ "x$DB_DOCKERFILE_DRIVER_XA_CLASS" != "x" ]
        then
            DOCKERFILE_STANDALONE_DRIVER_INTERNAL_TAG="<xa-datasource-class>$DB_DOCKERFILE_DRIVER_XA_CLASS</xa-datasource-class>"
        fi
        if[ "x$DB_DOCKERFILE_DRIVER_DRIVER_CLASS" != "x" ]
        then
            DOCKERFILE_STANDALONE_DRIVER_INTERNAL_TAG="<driver-class>$DB_DOCKERFILE_DRIVER_DRIVER_CLASS</driver-class>"
        fi
        DOCKERFILE_STANDALONE_DRIVER_TAG="<driver name=\"$DB_DOCKERFILE_DRIVER_NAME\" module=\"$DB_DOCKERFILE_DRIVER_MODULE\">$DOCKERFILE_STANDALONE_DRIVER_INTERNAL_TAG</driver>"
    fi

    # standalone1.xml
    sed -e "s#DOCKERFILE_STANDALONE_DATASOURCE_JNDI_NAME#$DB_DOCKERFILE_DATASOURCE_JNDI_NAME#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_CONNECTION_URL#$DB_DOCKERFILE_DATASOURCE_CONNECTION_URL#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_DRIVER#$DB_DOCKERFILE_DATASOURCE_DRIVER#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_DRV_CLASS#$DOCKERFILE_STANDALONE_DATASOURCE_DRIVER_CLASS_TAG#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_USERNAME#$DB_DOCKERFILE_DATASOURCE_USERNAME#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_PASSWORD#$DB_DOCKERFILE_DATASOURCE_PASSWORD#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION#$DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG#" \
        -e "s#DOCKERFILE_STANDALONE_DRIVER#$DOCKERFILE_STANDALONE_DRIVER_TAG#" \
        $DOCKERFILE_STANDALONE1_PATH > $2/standalone1.xml
    # standalone2.xml
    sed -e "s#DOCKERFILE_STANDALONE_DATASOURCE_JNDI_NAME#$DB_DOCKERFILE_DATASOURCE_JNDI_NAME#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_CONNECTION_URL#$DB_DOCKERFILE_DATASOURCE_CONNECTION_URL#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_DRIVER#$DB_DOCKERFILE_DATASOURCE_DRIVER#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_DRV_CLASS#$DOCKERFILE_STANDALONE_DATASOURCE_DRIVER_CLASS_TAG#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_USERNAME#$DB_DOCKERFILE_DATASOURCE_USERNAME#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_PASSWORD#$DB_DOCKERFILE_DATASOURCE_PASSWORD#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION#$DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG#" \
        -e "s#DOCKERFILE_STANDALONE_DRIVER#$DOCKERFILE_STANDALONE_DRIVER_TAG#" \
        $DOCKERFILE_STANDALONE2_PATH > $2/standalone2.xml
else
    echo "Updating env.sh script with database variables..."
    echo "export DB_DOCKERFILE_DATASOURCE_JNDI_NAME=$DB_DOCKERFILE_DATASOURCE_JNDI_NAME" >> $2/env.sh
    echo "export DB_DOCKERFILE_DATASOURCE_CONNECTION_URL=$DB_DOCKERFILE_DATASOURCE_CONNECTION_URL" >> $2/env.sh
    echo "export DB_DOCKERFILE_DATASOURCE_DRIVER=$DB_DOCKERFILE_DATASOURCE_DRIVER" >> $2/env.sh
    echo "export DB_DOCKERFILE_DATASOURCE_DRIVER_CLASS=$DB_DOCKERFILE_DATASOURCE_DRIVER_CLASS" >> $2/env.sh
    echo "export DB_DOCKERFILE_DATASOURCE_USERNAME=$DB_DOCKERFILE_DATASOURCE_USERNAME" >> $2/env.sh
    echo "export DB_DOCKERFILE_DATASOURCE_PASSWORD=$DB_DOCKERFILE_DATASOURCE_PASSWORD" >> $2/env.sh
    echo "export DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_SQL=$DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_SQL" >> $2/env.sh
    echo "export DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_CHECKER=$DB_DOCKERFILE_DATASOURCE_VALID_CONNECTION_CHECKER" >> $2/env.sh
    echo "export DB_DOCKERFILE_DRIVER_NAME=$DB_DOCKERFILE_DRIVER_NAME" >> $2/env.sh
    echo "export DB_DOCKERFILE_DRIVER_MODULE=$DB_DOCKERFILE_DRIVER_MODULE" >> $2/env.sh
    echo "export DB_DOCKERFILE_DRIVER_XA_CLASS=$DB_DOCKERFILE_DRIVER_XA_CLASS" >> $2/env.sh
    echo "export DB_DOCKERFILE_DRIVER_DRIVER_CLASS=$DB_DOCKERFILE_DRIVER_DRIVER_CLASS" >> $2/env.sh
fi
