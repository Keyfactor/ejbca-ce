#!/bin/sh

sudo su

# try those with sudo
# add the seluser guy to root group
cp /opt/ejbca_conf/* /app/ejbca/conf/
cp /opt/ejbca_webtest_conf/* /app/ejbca/modules/ejbca-webtest/conf/

/opt/bin/entry_point.sh &

sleep 10

# this should run eventually!
# ant test:webtest

# this one hangs!
# ant test:runone -Dtest.runone=EcaQa12_CPManagement

cd /app/ejbca



ant build

echo '=================== build finished ========================'

cat /etc/passwd

exit

whoami

# this test works in RA mode!
ant test:runone -Dtest.runone=EcaQa28_ServiceManagement
