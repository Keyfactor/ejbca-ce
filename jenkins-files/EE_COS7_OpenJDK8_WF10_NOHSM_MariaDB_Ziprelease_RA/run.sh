#!/bin/sh

# Options for JUnit JVM
export TEST_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for ant itself. The report building can be memory heavy, otherwise it shouldn't need much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx768m"
# Options for the CLI tools. These require very little memory.
# Note that the Wildfly CLI does not do escaping properly, so we can't use option values with spaces.
export JBOSSCLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -Xms32m -Xmx128m"
export EJBCACLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms32m -Xmx128m"

echo '=================== CHECKING JAVA VERSION: ================================='
java -version

ant ziprelease -Dedition=ee -Dvariant=ra -Ddoc.update=false -Drelease.revision=1d4b7b1ef8f8e23aefd49c45d903daee6c512d5a

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

JAVA_OPTS="$JBOSSCLI_OPTS" /opt/jboss/wildfly/bin/jboss-cli.sh -c --command=:reload
echo '=================== waiting 30... ========================'
sleep 30
wait_for_deployment
echo '=================== Wildfly restarted after deploy-keystore ========================'

JAVA_OPTS="$EJBCACLI_OPTS" bin/ejbca.sh ca importcacert ManagementCA ManagementCA.pem
JAVA_OPTS="$EJBCACLI_OPTS" bin/ejbca.sh roles addrolemember --role "Super Administrator Role" --caname ManagementCA --with WITH_COMMONNAME --value SuperAdmin
echo '=================== import cert commands done ========================'


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

echo "=================== All the files, that should be missing, are indeed properly missing ================================="

# Set an exit handler, that sets privileges for cleanup for the ziprelease package folder
workspacesubdir2=$(pwd)
cleanup() {
        echo '=================== cleanup. fixing permissions ================================='
        chown -R 1001:1001 "$workspacesubdir2"
}
trap cleanup EXIT
