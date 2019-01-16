#!/bin/sh


# try those with sudo
# add the seluser guy to root group
sudo -E env "PATH=$PATH" cp /opt/ejbca_conf/* /app/ejbca/conf/
sudo -E env "PATH=$PATH" cp /opt/ejbca_webtest_conf/* /app/ejbca/modules/ejbca-webtest/conf/

sudo -E env "PATH=$PATH" cp -rf /opt/jboss-ejb-client.properties /app/ejbca/src/appserver/jboss/jboss7/jboss-ejb-client.properties

/opt/bin/entry_point.sh &

sleep 10


cd /app/ejbca


echo '=================== Debug Info ========================'
# ls -la /home/seluser/.mozilla/firefox/svq3ko35.default
tail /app/ejbca/src/appserver/jboss/jboss7/jboss-ejb-client.properties

sudo -E env "PATH=$PATH" ant build

echo '=================== build finished ========================'



# this test works in RA mode!
#chown -R root /home/seluser
#ant test:runone -Dtest.runone=EcaQa28_ServiceManagement

# this one hangs?
ant test:runone -Dtest.runone=EcaQa12_CPManagement

# this should run eventually!
# ant test:webtest

