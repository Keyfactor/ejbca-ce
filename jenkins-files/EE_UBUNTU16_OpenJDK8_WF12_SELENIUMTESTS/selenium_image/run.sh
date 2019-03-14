#!/bin/sh

# Options for test JVM. The browser runs in a separate process, so it shouldn't need much memory
export JAVA_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx256m"
# Options for ant itself. The report building can be memory heavy, otherwise it shouldn't need much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx1536m"

# try those with sudo
# add the seluser guy to root group
sudo -E env "PATH=$PATH" cp /opt/ejbca_conf/* /app/ejbca/conf/
sudo -E env "PATH=$PATH" cp /opt/ejbca_webtest_conf/* /app/ejbca/modules/ejbca-webtest/conf/
sudo -E env "PATH=$PATH" cp /opt/propertyDefaults.xml /app/ejbca/propertyDefaults.xml
sudo -E env "PATH=$PATH" cp -rf /opt/jboss-ejb-client.properties /app/ejbca/src/appserver/jboss/jboss7/jboss-ejb-client.properties

/opt/bin/entry_point.sh &

sleep 10

cd /app/ejbca

# needs to be *clean* build, because otherwise the ejb remote configs won't be built into the package
sudo -E env "PATH=$PATH" "ANT_OPTS=$ANT_OPTS" "JAVA_OPTS=$JAVA_OPTS" ant clean build

echo '=================== build finished ========================'

ant test:webtest -Dtests.jvmargs="$JAVA_OPTS"
