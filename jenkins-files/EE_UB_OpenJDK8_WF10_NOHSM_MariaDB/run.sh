#!/bin/sh

cp /opt/standalone1.xml /opt/jboss/wildfly/standalone/configuration/standalone.xml

whoami

ls -la /app/ejbca/conf/
ls -la /opt/conf/

cp /opt/conf/* /app/ejbca/conf/

/opt/jboss/wildfly/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 &

ant clean deployear

echo '=================== Waiting for deploy ================================='


wait_for_deployment() {
	# Wait for up to 180 seconds for app to start up
	for i in {1..90} ; do
		if [ -e "/opt/jboss/wildfly/standalone/deployments/ejbca.ear.deployed" ] ; then
			echo "EJBCA successfully started."
			break
		fi
		echo 'waiting...'
		sleep 2
	done
#TODO what about deploy failure case??
}

wait_for_deployment
echo '=================== ant deployear done and successfully deployed! ================================='

ant runinstall
echo '=================== ant runinstall done! ================================='

ant deploy-keystore
echo '=================== ant deploy-keystore done! ================================='

cp /opt/standalone2.xml /opt/jboss/wildfly/standalone/configuration/standalone.xml
/opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload

# wait for reload to kick in and start undeploying and drop ejbca.ear.deployed file (otherwise we'd detect ejbca.ear.deployed file immediately again)
sleep 10

wait_for_deployment

echo '=================== starting system tests ================================='
ant test:runsys
