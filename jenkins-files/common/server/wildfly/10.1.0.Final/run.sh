#!/usr/bin/env bash

. /opt/env.sh

# Stage flags
APP_FOLDER="/app"
STAGE_STANDALONE1_FLAG="${APP_FOLDER}/STAGE0_STANDALONE1.flag"
STAGE_RUNINSTALL_FLAG="${APP_FOLDER}/STAGE1_RUNINSTALL.flag"
STAGE_DEPLOY_KEYSTORE_FLAG="${APP_FOLDER}/STAGE2_DEPLOY_KEYSTORE.flag"
STAGE_STANDALONE2_FLAG="${APP_FOLDER}/STAGE3_STANDALONE2.flag"

echo '=================== Java Version ==========================================='
java -version

if [ ! -f "${STAGE_STANDALONE1_FLAG}" ]
then
    echo '=================== Copying Configuration 1 ================================'
    cp /opt/standalone1.xml $JBOSS_STANDALONE_CONF/standalone.xml
    if [ -f /opt/deployments/dbdriver.jar ]
    then
        echo '=================== Adding dbdriver.jar to deployments ====================='
        cp /opt/deployments/dbdriver.jar /opt/jboss/wildfly/standalone/deployments/
    fi
    echo '=================== Starting WildFly ======================================='
    $JBOSS_BIN/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 > /app/standalone.log &
    echo '=================== Waiting for Server ====================================='
    wait_for_server
    echo '=================== Copying Deployment ====================================='
    cp /app/ejbca/dist/ejbca.ear $JBOSS_STANDALONE_DEPLOYMENTS/
    echo '=================== Waiting for Deployment ================================='
    wait_for_deployment
    touch "${STAGE_STANDALONE1_FLAG}"
fi

if [ ! -f "${STAGE_RUNINSTALL_FLAG}" ]
then
    echo '=================== Starting runinstall====================================='
    ant runinstall
    echo '=================== ant runinstall done! ==================================='
    touch "${STAGE_RUNINSTALL_FLAG}"
fi

if [ ! -f "${STAGE_DEPLOY_KEYSTORE_FLAG}" ]
then
    echo '=================== Starting deploy-keystore ==============================='
    ant deploy-keystore
    echo '=================== ant deploy-keystore done! =============================='
    touch "${STAGE_DEPLOY_KEYSTORE_FLAG}"
fi

if [ ! -f "${STAGE_STANDALONE2_FLAG}" ]
then
    echo '=================== Replacing Configuration 1 with 2 and Reloading ========='
    cp /opt/standalone2.xml $JBOSS_STANDALONE_CONF/standalone.xml
    JAVA_OPTS="$JBOSSCLI_OPTS" $JBOSS_CLI -c --command=:reload
    echo '=================== Waiting for 60 s ======================================='
    # wait for reload to kick in and start undeploying and drop ejbca.ear.deployed file (otherwise we'd detect ejbca.ear.deployed file immediately again)
    sleep 60
    echo '=================== Waiting for Server ====================================='
    wait_for_server
    echo '=================== Waiting for deployment ================================='
    wait_for_deployment
    echo '=================== Deployment is done ====================================='
    echo '=================== Shutting down Server ==================================='
    JAVA_OPTS="$JBOSSCLI_OPTS" $JBOSS_CLI -c --command=:shutdown
    echo '=================== Waiting for 60 s ======================================='
    sleep 60
    touch "${STAGE_STANDALONE2_FLAG}"
fi

echo '=================== Starting WildFly ======================================='
$JBOSS_BIN/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0
