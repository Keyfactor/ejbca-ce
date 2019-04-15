#!/bin/sh

# Options for ant itself. Report building is done in selenium_image, so this shouldn't require much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for the CLI tools. These require very little memory.
# Note that the Wildfly CLI does not do escaping properly, so we can't use option values with spaces.
export JBOSSCLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -Xms32m -Xmx128m"
export EJBCACLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms32m -Xmx128m"

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

ant runinstall
ant deploy-keystore
echo '=================== deploy-keystore done ========================'

JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command="/socket-binding-group=standard-sockets/remote-destination-outbound-socket-binding=ejbca-mail-smtp:add(port="993", host="my.mail.server")"
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command='/subsystem=mail/mail-session="java:/EjbcaMail":add(jndi-name=java:/EjbcaMail, from=noreply@mymail)'
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command='/subsystem=mail/mail-session="java:/EjbcaMail"/server=smtp:add(outbound-socket-binding-ref=ejbca-mail-smtp, tls=true, username=smtpuser, password=smtppassword)'

JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload
echo '=================== waiting 30... ========================'
sleep 30
wait_for_deployment
echo '=================== Wildfly restarted after deploy-keystore ========================'

#JAVA_OPTS="$EJBCACLI_OPTS" bin/ejbca.sh ca importcacert ManagementCA ManagementCA.pem
#JAVA_OPTS="$EJBCACLI_OPTS" bin/ejbca.sh roles addrolemember --role "Super Administrator Role" --caname ManagementCA --with WITH_COMMONNAME --value SuperAdmin

# manually change the "status" of CA from external -> active

echo '=================== import cert commands done ========================'

# stay alive until UI tests finish. otherwise the container would just be closed and UI tests would not be able to use it anymore
sleep 10000000
