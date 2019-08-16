#!/bin/sh

# This utility script defines the application server docker artifacts and copies them.
# copyAppDocker.sh JENKINS_FILES_SERVER BUILD_FOLDER DOCKER_NAME_DB JDK_VERSION DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                  [1]                  [2]          [3]            [4]         [5]       [6]        [7]           [8]
#echo
#echo "copyAppDocker.sh [$1] [$2] [$3] [$4] [$5] [$6] [$7] [$8]"
#echo

########################################################################################################################
# Variables
########################################################################################################################
DOCKERFILE_PATH=""
DOCKERFILE_ENV_PATH=""
DOCKERFILE_RUN_PATH=""
DOCKERFILE_STANDALONE_FILTERED=false
DOCKERFILE_STANDALONE1_PATH=""
DOCKERFILE_STANDALONE2_PATH=""
DOCKERFILE_STANDALONE_DATASOURCE_DRIVER_CLASS_TAG=""
DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG=""
DOCKERFILE_STANDALONE_DRIVER_TAG=""

########################################################################################################################
# Setup variables
########################################################################################################################
if [ $7 = "wildfly" ]
then
    if [ -f "$1/$7/$8/Dockerfile" ]
    then
        DOCKERFILE_PATH="$1/$7/$8/Dockerfile"
        DOCKERFILE_ENV_PATH="$1/$7/$8/env.sh"
        DOCKERFILE_RUN_PATH="$1/$7/$8/run.sh"
        DOCKERFILE_STANDALONE_FILTERED=true
        DOCKERFILE_STANDALONE1_PATH="$1/$7/$8/standalone1.xml"
        DOCKERFILE_STANDALONE2_PATH="$1/$7/$8/standalone2.xml"
    else
        echo "Error: Cannot find the WildFly container with version $6"
        exit 1
    fi
else
    echo "Error: Cannot map the application server family"
    exit 1
fi

########################################################################################################################
# Copy resources
########################################################################################################################
cp $DOCKERFILE_PATH $2/
cp $DOCKERFILE_ENV_PATH $2/
cp $DOCKERFILE_RUN_PATH $2/

if [ "$DOCKERFILE_STANDALONE_FILTERED" = true ]
then
    # Wrap <driver-class/>
    if [ ! -z "$DB_DATASOURCE_DRIVER_CLASS" ]
    then
        DOCKERFILE_STANDALONE_DATASOURCE_DRIVER_CLASS_TAG="<driver-class>$DB_DATASOURCE_DRIVER_CLASS</driver-class>"
    fi
    # Wrap <check-valid-connection-sql/>
    if [ ! -z "$DB_DATASOURCE_VALID_CONNECTION_SQL" ]
    then
        DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG="<check-valid-connection-sql>$DB_DATASOURCE_VALID_CONNECTION_SQL</check-valid-connection-sql>"
    fi
    # Wrap <valid-connection-checker/>
    if [ ! -z "$DB_DATASOURCE_VALID_CONNECTION_CHECKER" ]
    then
        DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG="<valid-connection-checker class-name=\"$DB_DATASOURCE_VALID_CONNECTION_CHECKER\"/>"
    fi
    # Wrap <driver/>
    if [ ! -z "$DB_DRIVER_NAME" ]
    then
        DOCKERFILE_STANDALONE_DRIVER_INTERNAL_TAG=""
        # Wrap <xa-datasource-class/>
        if [ ! -z "$DB_DRIVER_XA_CLASS" ]
        then
            DOCKERFILE_STANDALONE_DRIVER_INTERNAL_TAG="<xa-datasource-class>$DB_DRIVER_XA_CLASS</xa-datasource-class>"
        fi
        # Wrap <driver-class/>
        if [ ! -z "$DB_DRIVER_DRIVER_CLASS" ]
        then
            DOCKERFILE_STANDALONE_DRIVER_INTERNAL_TAG="<driver-class>$DB_DRIVER_DRIVER_CLASS</driver-class>"
        fi
        DOCKERFILE_STANDALONE_DRIVER_TAG="<driver name=\"$DB_DRIVER_NAME\" module=\"$DB_DRIVER_MODULE\">$DOCKERFILE_STANDALONE_DRIVER_INTERNAL_TAG</driver>"
    fi

#    echo "standalone.xml Replacement Variables:"
#    echo "DOCKERFILE_STANDALONE_DATASOURCE_JNDI_NAME        [$DB_DATASOURCE_JNDI_NAME]"
#    echo "DOCKERFILE_STANDALONE_DATASOURCE_CONNECTION_URL   [$DB_DATASOURCE_CONNECTION_URL]"
#    echo "DOCKERFILE_STANDALONE_DATASOURCE_DRIVER           [$DB_DATASOURCE_DRIVER]"
#    echo "DOCKERFILE_STANDALONE_DATASOURCE_DRV_CLASS        [$DOCKERFILE_STANDALONE_DATASOURCE_DRIVER_CLASS_TAG]"
#    echo "DOCKERFILE_STANDALONE_DATASOURCE_USERNAME         [$DB_DATASOURCE_USERNAME]"
#    echo "DOCKERFILE_STANDALONE_DATASOURCE_PASSWORD         [$DB_DATASOURCE_PASSWORD]"
#    echo "DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION [$DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG]"
#    echo "DOCKERFILE_STANDALONE_DRIVER                      [$DOCKERFILE_STANDALONE_DRIVER_TAG]"

    # standalone1.xml
    sed -e "s#DOCKERFILE_STANDALONE_DATASOURCE_JNDI_NAME#$DB_DATASOURCE_JNDI_NAME#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_CONNECTION_URL#$DB_DATASOURCE_CONNECTION_URL#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_DRIVER#$DB_DATASOURCE_DRIVER#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_DRV_CLASS#$DOCKERFILE_STANDALONE_DATASOURCE_DRIVER_CLASS_TAG#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_USERNAME#$DB_DATASOURCE_USERNAME#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_PASSWORD#$DB_DATASOURCE_PASSWORD#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION#$DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG#" \
        -e "s#DOCKERFILE_STANDALONE_DRIVER#$DOCKERFILE_STANDALONE_DRIVER_TAG#" \
        $DOCKERFILE_STANDALONE1_PATH > $2/standalone1.xml

    # standalone2.xml
    sed -e "s#DOCKERFILE_STANDALONE_DATASOURCE_JNDI_NAME#$DB_DATASOURCE_JNDI_NAME#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_CONNECTION_URL#$DB_DATASOURCE_CONNECTION_URL#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_DRIVER#$DB_DATASOURCE_DRIVER#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_DRV_CLASS#$DOCKERFILE_STANDALONE_DATASOURCE_DRIVER_CLASS_TAG#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_USERNAME#$DB_DATASOURCE_USERNAME#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_PASSWORD#$DB_DATASOURCE_PASSWORD#" \
        -e "s#DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION#$DOCKERFILE_STANDALONE_DATASOURCE_VALID_CONNECTION_TAG#" \
        -e "s#DOCKERFILE_STANDALONE_DRIVER#$DOCKERFILE_STANDALONE_DRIVER_TAG#" \
        $DOCKERFILE_STANDALONE2_PATH > $2/standalone2.xml
fi
