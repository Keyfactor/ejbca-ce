#!/bin/sh

# Options for JUnit JVM
export TEST_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for ant itself. The report building can be memory heavy, otherwise it shouldn't need much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for the CLI tools that require little memory, like the JBoss CLI
export CLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx128m"

# Function that is always run at exit
workspacesubdir=$(pwd)
cleanup() {
        echo '=================== cleanup. fixing permissions ================================='
        chown -R 1001:1001 "$workspacesubdir"
}
trap cleanup EXIT

echo '=================== CHECKING JAVA VERSION: ================================='
java -version

cp /opt/standalone1.xml /opt/jboss/wildfly/standalone/configuration/standalone.xml


ant ziprelease -Dedition=ee -Dvariant=ra -Ddoc.update=false -Drelease.revision=12345

cd ..

find . -name "ejbca*.zip" | xargs unzip

echo '=================== fixing permissions in the original source folder ================================='
chown -R 1001:1001 .

cd ejbca_ee*

cp /opt/conf/* ./conf/


/opt/jboss/wildfly/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 &

ant clean deployear


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

echo '=================== Waiting for deploy ================================='
wait_for_deployment

echo '=================== ant deployear done and successfully deployed! ================================='

#ant runinstall
echo '=================== ant runinstall done! ================================='

#ant deploy-keystore
echo '=================== ant deploy-keystore done! ================================='

# load the final version of Wildfly conf and restart wildfly
#cp /opt/standalone2.xml /opt/jboss/wildfly/standalone/configuration/standalone.xml
#JAVA_OPTS="$CLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload

# wait for reload to kick in and start undeploying and drop ejbca.ear.deployed file (otherwise we'd detect ejbca.ear.deployed file immediately again)
sleep 10

wait_for_deployment

echo '=================== verify that VA and the X509CA and CVCCA implementation classes are missing ================================='

if [ -f ./modules/va/src-war/org/ejbca/ui/web/protocol/OCSPServlet.java ]; then
    echo "RA-only build should not contain OCSPServlet.java"
    exit 1;
fi

if [ -f ./modules/va/resources/WEB-INF/web-status-ejbca.xml ]; then
    echo "RA-only build should not contain web-status-ejbca.xml"
    exit 1;
fi

if [ -d ./modules/cesecore-cvcca ]; then
    echo "RA-only build should not contain cesecore-cvcca module"
    exit 1;
fi

if [ -d ./modules/cesecore-x509ca ]; then
    echo "RA-only build should not contain cesecore-x509ca module"
    exit 1;
fi

echo "====== All the files, that should be missing, seem to be properly missing ======"

