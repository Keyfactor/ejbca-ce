#!/bin/sh

# Options for JUnit JVM
export TEST_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for ant itself. The report building can be memory heavy, otherwise it shouldn't need much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for the CLI tools that require little memory, like the JBoss CLI
export CLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx128m"

# Set an exit handler, that sets privileges for cleanup for the initial source folder
workspacesubdir=$(pwd)
cleanup() {
        echo '=================== cleanup. fixing permissions ================================='
        chown -R 1001:1001 "$workspacesubdir"
}
trap cleanup EXIT

echo '=================== CHECKING JAVA VERSION: ================================='
java -version

ant ziprelease -Dedition=ee -Dvariant=va -Ddoc.update=false -Drelease.revision=12345

cd ..

find . -name "ejbca*.zip" | xargs unzip

echo '=================== fixing permissions in the original source folder ================================='
chown -R 1001:1001 .

cd ejbca_ee*

cp /opt/conf/* ./conf/

mkdir -p p12
cp /opt/p12/* ./p12/

cp /opt/ManagementCA.pem ./ManagementCA.pem

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

echo '=================== should be started now ========================'

ant deploy-keystore
echo '=================== deploy-keystore done ========================'

/opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload
echo '=================== waiting 30... ========================'
sleep 30
wait_for_deployment
echo '=================== Wildfly restarted after deploy-keystore ========================'

bin/ejbca.sh ca importcacert ManagementCA ManagementCA.pem
bin/ejbca.sh roles addrolemember --role "Super Administrator Role" --caname ManagementCA --with WITH_COMMONNAME --value SuperAdmin
echo '=================== import cert commands done ========================'


echo '=================== verify that RA and the X509CA and CVCCA implementation classes are missing ================================='

if [ -f .modules/peerconnector/src-ra/org/ejbca/peerconnector/ra/RaMasterApiPeerImpl.java ]; then
    echo "VA-only build should not contain RaMasterApiPeerImpl.java"
    exit 1;
fi

if [ -f .modules/peerconnector/src-ra/org/ejbca/peerconnector/ra/RaMasterApiPeerDownstreamImpl.java ]; then
    echo "VA-only build should not contain RaMasterApiPeerDownstreamImpl"
    exit 1;
fi

if [ -f .modules/peerconnector/src-ra/org/ejbca/peerconnector/ra/RaMasterApiPeerUpstreamImpl.java ]; then
    echo "VA-only build should not contain RaMasterApiPeerUpstreamImpl"
    exit 1;
fi

if [ -d ./modules/ra-gui ]; then
    echo "VA-only build should not contain ra-gui module"
    exit 1;
fi

if [ -d ./modules/cesecore-cvcca ]; then
    echo "VA-only build should not contain cesecore-cvcca module"
    exit 1;
fi

if [ -d ./modules/cesecore-x509ca ]; then
    echo "VA-only build should not contain cesecore-x509ca module"
    exit 1;
fi

echo "=================== All the files, that should be missing, are indeed properly missing ================================="

# Set an exit handler, that sets privileges for cleanup for the ziprelease package folder
workspacesubdir2=$(pwd)
cleanup() {
        echo '=================== cleanup. fixing permissions ================================='
        chown -R 1001:1001 "$workspacesubdir2"
}
trap cleanup EXIT