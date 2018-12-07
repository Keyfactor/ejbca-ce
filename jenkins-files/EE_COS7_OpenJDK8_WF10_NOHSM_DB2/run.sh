#!/bin/sh

# JBoss
JBOSS_HOME=/opt/jboss/wildfly
JBOSS_BIN=$JBOSS_HOME/bin
JBOSS_CLI=$JBOSS_HOME/bin/jboss-cli.sh
JBOSS_STANDALONE=$JBOSS_HOME/standalone
JBOSS_STANDALONE_CONF=$JBOSS_STANDALONE/configuration
JBOSS_STANDALONE_DEPLOYMENTS=$JBOSS_STANDALONE/deployments

echo $JBOSS_HOME
echo $JBOSS_BIN
echo $JBOSS_CLI
echo $JBOSS_STANDALONE
echo $JBOSS_STANDALONE_CONF
echo $JBOSS_STANDALONE_DEPLOYMENTS

# Functions
wait_for_deployment() {
	DEPLOY_SUCCESSFUL=0
	# Wait for up to 180 seconds for app to start up
	for i in {1..90} ; do
		if [ -e `$JBOSS_STANDALONE_DEPLOYMENTS/ejbca.ear.deployed` ] ; then
			echo "EJBCA successfully started."
			DEPLOY_SUCCESSFUL=1
			break
		fi
		if [ -e `$JBOSS_STANDALONE_DEPLOYMENTS/ejbca.ear.failed` ] ; then
			echo "EJBCA deploy failed."
			exit 1;
		fi
		echo 'waiting...'
		sleep 2
	done
	if [ "$DEPLOY_SUCCESSFUL" -ne 1 ]; then
		echo "EJBCA deploy timed out." 
		exit 1;
	fi
}


echo '=================== Checking Java Version =================================='
java -version

echo '=================== Copying Configuration =================================='
cp /opt/standalone1.xml $JBOSS_STANDALONE_CONF/standalone.xml
cp /opt/conf/* /app/ejbca/conf/


echo '=================== Starting WildFly ======================================='
$JBOSS_BIN/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 &

#echo '=================== Installing DB2 JDBC Driver and Datasource =============='
#`$JBOSS_CLI data-source add --name=EjbcaDS \
#                            --driver-name="com.ibm.db2.jcc.DB2Driver" \
#                            --connection-url="jdbc:db2://$DOCKER_NAME_DB:50000/ejbca" \
#                            --jndi-name="java:/EjbcaDS" \
#                            --use-ccm=true \
#                            --driver-class="com.ibm.db2.jcc.DB2Driver" \
#                            --user-name="db2inst1" \
#                            --password="db2inst1" \
#                            --validate-on-match=false \
#                            --background-validation=false \
#                            --prepared-statements-cache-size=50 \
#                            --share-prepared-statements=true \
#                            --min-pool-size=5 \
#                            --max-pool-size=20 \
#                            --pool-prefill=true \
#                            --transaction-isolation=TRANSACTION_READ_COMMITTED \
#                            --jta=false \
#                            --check-valid-connection-sql="select 1;"`

echo '=================== Starting clean/build/deployment ========================'
ant clean deployear

echo '=================== Waiting for deployment ================================='
wait_for_deployment
echo '=================== ant deployear done and successfully deployed! =========='

echo '=================== Starting install ======================================='
ant runinstall
echo '=================== ant runinstall done! ==================================='

echo '=================== Starting keystore deployment ==========================='
ant deploy-keystore
echo '=================== ant deploy-keystore done! =============================='

echo '=================== Replacing Configuration and Reloading =================='
cp /opt/standalone2.xml $JBOSS_STANDALONE_CONF/standalone.xml
$JBOSS_CLI -c --command=:reload

# wait for reload to kick in and start undeploying and drop ejbca.ear.deployed file (otherwise we'd detect ejbca.ear.deployed file immediately again)
sleep 10

echo '=================== Waiting for deployment ================================='
wait_for_deployment
echo '=================== Deployment is done ====================================='

echo '=================== Starting system tests =================================='
ant test:runsys
echo '=================== System tests are done =================================='

