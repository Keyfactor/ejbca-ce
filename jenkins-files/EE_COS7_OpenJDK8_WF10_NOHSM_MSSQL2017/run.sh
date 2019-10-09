#!/bin/sh

# JBoss
JBOSS_HOME=/opt/jboss/wildfly
JBOSS_BIN=$JBOSS_HOME/bin
JBOSS_CLI=$JBOSS_HOME/bin/jboss-cli.sh
JBOSS_STANDALONE=$JBOSS_HOME/standalone
JBOSS_STANDALONE_CONF=$JBOSS_STANDALONE/configuration
JBOSS_STANDALONE_DEPLOYMENTS=$JBOSS_STANDALONE/deployments

# Options for JUnit JVM
export TEST_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for ant itself. The report building can be memory heavy, otherwise it shouldn't need much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx768m"
# Options for the CLI tools. These require very little memory.
# Note that the Wildfly CLI does not do escaping properly, so we can't use option values with spaces.
export JBOSSCLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -Xms32m -Xmx128m"

wait_for_deployment() {
	DEPLOY_SUCCESSFUL=0
	# Wait for up to 180 seconds for app to start up
	for i in {1..90} ; do
		if [ -e "$JBOSS_STANDALONE_DEPLOYMENTS/ejbca.ear.deployed" ] ; then
			echo "EJBCA successfully started."
			DEPLOY_SUCCESSFUL=1
			break
		fi
		if [ -e "$JBOSS_STANDALONE_DEPLOYMENTS/ejbca.ear.failed" ] ; then
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
JAVA_OPTS="$JBOSSCLI_OPTS" $JBOSS_CLI -c --command=:reload

# wait for reload to kick in and start undeploying and drop ejbca.ear.deployed file (otherwise we'd detect ejbca.ear.deployed file immediately again)
sleep 10

echo '=================== Waiting for deployment ================================='
wait_for_deployment
echo '=================== Deployment is done ====================================='

echo '=================== Starting system tests =================================='
ant test:runsys -Dtests.jvmargs="$TEST_OPTS"
echo '=================== System tests are done =================================='
