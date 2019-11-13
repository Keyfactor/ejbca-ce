#!/bin/sh

# Options for JUnit JVM
export TEST_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for ant itself. The report building can be memory heavy, otherwise it shouldn't need much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx768m"
# Options for the CLI tools. These require very little memory.
# Note that the Wildfly CLI does not do escaping properly, so we can't use option values with spaces.
export JBOSSCLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -Xms32m -Xmx128m"

echo '=================== CHECKING JAVA VERSION: ================================='
java -version

cp /opt/standalone1.xml /opt/jboss/wildfly/standalone/configuration/standalone.xml

cp /opt/conf/* /app/ejbca/conf/

/opt/jboss/wildfly/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 &

ant clean deployear

echo '=================== Waiting for deploy ================================='


wait_for_deployment() {
    DEPLOY_SUCCESSFUL=0
	# Wait for up to 180 seconds for app to start up
	for i in {1..90} ; do
		if [ -e "/opt/jboss/wildfly/standalone/deployments/ejbca.ear.deployed" ] ; then
			echo "EJBCA successfully started."
			DEPLOY_SUCCESSFUL=1
			break
		fi
		if [ -e "/opt/jboss/wildfly/standalone/deployments/ejbca.ear.failed" ] ; then
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

wait_for_deployment
echo '=================== ant deployear done and successfully deployed! ================================='

mysql -u ejbca -pejbca -h mariadb_softhsm < doc/sql-scripts/create-index-ejbca.sql
echo '=================== adding database indexes done! ================================'

ant runinstall
echo '=================== ant runinstall done! ================================='

ant deploy-keystore
echo '=================== ant deploy-keystore done! ================================='

# load the final version of Wildfly conf and restart wildfly
cp /opt/standalone2.xml /opt/jboss/wildfly/standalone/configuration/standalone.xml
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload

# wait for reload to kick in and start undeploying and drop ejbca.ear.deployed file (otherwise we'd detect ejbca.ear.deployed file immediately again)
sleep 10

wait_for_deployment

echo '=================== starting system tests ================================='

ant test:run -Dtest.includep11=true -Dtests.jvmargs="$TEST_OPTS"

