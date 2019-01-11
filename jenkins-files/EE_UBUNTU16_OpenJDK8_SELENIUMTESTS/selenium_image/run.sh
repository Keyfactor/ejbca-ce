#!/bin/sh

# try those with sudo
# add the seluser guy to root group
sudo -E env "PATH=$PATH" cp /opt/ejbca_conf/* /app/ejbca/conf/
sudo -E env "PATH=$PATH" cp /opt/ejbca_webtest_conf/* /app/ejbca/modules/ejbca-webtest/conf/

/opt/bin/entry_point.sh &

sleep 10

# this should run eventually!
# ant test:webtest

# this one hangs!
# ant test:runone -Dtest.runone=EcaQa12_CPManagement

cd /app/ejbca



#sudo -E env "PATH=$PATH" ant build

echo '=================== build finished ========================'

#chown -R root /home/seluser

sudo -E env "PATH=$PATH" mkdir -p /app/ejbca/modules/ejbca-webtest/build/classes
sudo -E env "PATH=$PATH" chmod 777 /app/ejbca/modules/ejbca-webtest/build/classes

# this test works in RA mode!
ant test:runone -Dtest.runone=EcaQa28_ServiceManagement
