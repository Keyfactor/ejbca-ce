#!/bin/sh

# Options for ant itself. Report building is done in selenium_image, so this shouldn't require much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for the CLI tools that require little memory, like the JBoss CLI
export CLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx128m"

cp /opt/conf/* /app/ejbca/conf/
cp /opt/p12/* /app/ejbca/p12/
cp /opt/ManagementCA.pem /app/ejbca/ManagementCA.pem

echo "P12 contents"
ls -la /app/ejbca/p12/

/opt/jboss/wildfly/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 &


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

ant clean deployear
wait_for_deployment
echo '=================== should be started now ========================'

ant deploy-keystore
echo '=================== deploy-keystore done ========================'

JAVA_OPTS="$CLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload
echo '=================== waiting 30... ========================'
sleep 30
wait_for_deployment
echo '=================== Wildfly restarted after deploy-keystore ========================'

bin/ejbca.sh ca importcacert ManagementCA ManagementCA.pem
bin/ejbca.sh roles addrolemember --role "Super Administrator Role" --caname ManagementCA --with WITH_COMMONNAME --value SuperAdmin
echo '=================== import cert commands done ========================'

# stay alive until UI tests finish. otherwise the container would just be closed and UI tests would not be able to use it anymore
sleep 10000000
