#!/bin/sh

# Options for test JVM. The browser runs in a separate process, so it shouldn't need much memory
export TEST_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx1536m"
# Options for ant itself. The report building can be memory heavy, otherwise it shouldn't need much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx256m"

cp /opt/ejbca_conf/* /app/ejbca/conf/
cp /opt/ejbca_webtest_conf/* /app/ejbca/modules/ejbca-webtest/conf/
cp /opt/propertyDefaults.xml /app/ejbca/propertyDefaults.xml
cp -rf /opt/jboss-ejb-client.properties /app/ejbca/src/appserver/jboss/jboss7/jboss-ejb-client.properties

/opt/bin/entry_point.sh &

sleep 10

cd /app/ejbca

# needs to be *clean* build, because otherwise the ejb remote configs won't be built into the package
ant clean build

echo '=================== build finished ========================'

ls -la /app/ejbca/modules/ejbca-webtest/resources

ant ejbca:setup:selenium -Dbrowser.firefox.binary=/usr/bin/firefox -Denv.HOME=/home/jenkins
ant test:webtest:jenkins -Dtests.jvmargs="$TEST_OPTS"

