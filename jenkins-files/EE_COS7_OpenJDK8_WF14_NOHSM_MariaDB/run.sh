#!/bin/sh

# Options for JUnit JVM
export TEST_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for ant itself. The report building can be memory heavy, otherwise it shouldn't need much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx768m"
# Options for the CLI tools. These require very little memory.
# Note that the Wildfly CLI does not do escaping properly, so we can't use option values with spaces.
export JBOSSCLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -Xms32m -Xmx128m"

wait_for_deployment() {
	echo '=================== Waiting for deploy =========================='
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
        echo '============ Application Server log ============='
        cat /opt/jboss/wildfly/standalone/log/server.log 
        exit 1;
    fi
}

echo '=================== CHECKING JAVA VERSION: =========================='
java -version

cp /opt/conf/* /app/ejbca/conf/

echo '=================== Starting Application Server ====================='
/opt/jboss/wildfly/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 &
sleep 10

echo '=================== Adding Datasource ==============================='
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command='data-source add --name=ejbcads --driver-name="mariadb-java-client.jar" --connection-url="jdbc:mysql://mariadb_wf14_1:3306/ejbca" --jndi-name="java:/EjbcaDS" --use-ccm=true --driver-class="org.mariadb.jdbc.Driver" --user-name="ejbca" --password="ejbca" --validate-on-match=true --background-validation=false --prepared-statements-cache-size=50 --share-prepared-statements=true --min-pool-size=5 --max-pool-size=150 --pool-prefill=true --transaction-isolation=TRANSACTION_READ_COMMITTED --check-valid-connection-sql="select 1;"'
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload
sleep 10

echo '=================== Configuring Remote Interfaces ==================='
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c <<EOF
/subsystem=remoting/http-connector=http-remoting-connector:write-attribute(name=connector-ref,value=remoting)
/socket-binding-group=standard-sockets/socket-binding=remoting:add(port=4447,interface=management)
/subsystem=undertow/server=default-server/http-listener=remoting:add(socket-binding=remoting,enable-http2=true)
/subsystem=infinispan/cache-container=ejb:remove()
/subsystem=infinispan/cache-container=server:remove()
/subsystem=infinispan/cache-container=web:remove()
/subsystem=ejb3/cache=distributable:remove()
/subsystem=ejb3/passivation-store=infinispan:remove()
EOF
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload
sleep 10

echo '=================== Configuring logging ============================='
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c <<EOF
/subsystem=logging/logger=org.ejbca:add(level=INFO)
/subsystem=logging/logger=org.cesecore:add(level=INFO)
EOF

echo '=================== Deploying EJBCA ================================='
ant -q clean deployear

wait_for_deployment
echo '=================== Deployment Done ================================='

ant -q runinstall
echo '=================== Runinstall Done ================================='

ant -q deploy-keystore
echo '=================== Keystore Deployed ==============================='

echo '=================== Removing existing TLS and HTTP configuration ===='
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c <<EOF
/subsystem=undertow/server=default-server/http-listener=default:remove()
/subsystem=undertow/server=default-server/https-listener=https:remove()
/socket-binding-group=standard-sockets/socket-binding=http:remove()
/socket-binding-group=standard-sockets/socket-binding=https:remove()
EOF
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload

sleep 10
wait_for_deployment

echo '=================== Adding new interfaces and sockets ==============='
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c <<EOF
/interface=http:add(inet-address="0.0.0.0")
/interface=httpspub:add(inet-address="0.0.0.0")
/interface=httpspriv:add(inet-address="0.0.0.0")
/socket-binding-group=standard-sockets/socket-binding=http:add(port="8080",interface="http")
/socket-binding-group=standard-sockets/socket-binding=httpspub:add(port="8442",interface="httpspub")
/socket-binding-group=standard-sockets/socket-binding=httpspriv:add(port="8443",interface="httpspriv")
EOF

echo '=================== Configuring TLS ================================='
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c <<EOF
/subsystem=elytron/key-store=httpsKS:add(path="keystore/keystore.jks",relative-to=jboss.server.config.dir,credential-reference={clear-text="serverpwd"},type=JKS)
/subsystem=elytron/key-store=httpsTS:add(path="keystore/truststore.jks",relative-to=jboss.server.config.dir,credential-reference={clear-text="changeit"},type=JKS)
/subsystem=elytron/key-manager=httpsKM:add(key-store=httpsKS,algorithm="SunX509",credential-reference={clear-text="serverpwd"})
/subsystem=elytron/trust-manager=httpsTM:add(key-store=httpsTS)
/subsystem=elytron/server-ssl-context=httpspub:add(key-manager=httpsKM,protocols=["TLSv1.2"])
/subsystem=elytron/server-ssl-context=httpspriv:add(key-manager=httpsKM,protocols=["TLSv1.2"],trust-manager=httpsTM,need-client-auth=true,authentication-optional=false,want-client-auth=true
EOF

echo '=================== Adding HTTP(S) listeners ========================'
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c <<EOF
/subsystem=undertow/server=default-server/http-listener=http:add(socket-binding="http", redirect-socket="httpspriv")
/subsystem=undertow/server=default-server/https-listener=httpspub:add(socket-binding="httpspub", ssl-context="httpspub", max-parameters=2048)
/subsystem=undertow/server=default-server/https-listener=httpspriv:add(socket-binding="httpspriv", ssl-context="httpspriv", max-parameters=2048)
EOF

JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload
sleep 10
wait_for_deployment

echo '=================== Configuring HTTP Protocol Behavior =============='
JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c <<EOF
/system-property=org.apache.catalina.connector.URI_ENCODING:add(value="UTF-8")
/system-property=org.apache.catalina.connector.USE_BODY_ENCODING_FOR_QUERY_STRING:add(value=true)
/system-property=org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH:add(value=true)
/system-property=org.apache.tomcat.util.http.Parameters.MAX_COUNT:add(value=2048)
/system-property=org.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH:add(value=true)
/subsystem=webservices:write-attribute(name=wsdl-host, value=jbossws.undefined.host)
/subsystem=webservices:write-attribute(name=modify-wsdl-address, value=true)
EOF

JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload
sleep 10
wait_for_deployment

echo '=================== starting system tests ==========================='
ant test:runsys -Dtests.jvmargs="$TEST_OPTS"



