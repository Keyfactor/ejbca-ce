#!/bin/sh

echo "curl styles:"
curl http://mypeer:8080/ejbca/styles.css

cd /app/ejbca/p12
openssl pkcs12 -in superadmin.p12 -out superadmin.key.pem -nocerts -nodes
openssl pkcs12 -in superadmin.p12 -out superadmin.crt.pem -clcerts -nokeys
curl -E superadmin.crt.pem --key superadmin.key.pem https://mypeer:8443/ejbca/adminweb/




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


echo '=================== Profile folder contents ========================'
ls -la /home/seluser/.mozilla/firefox/svq3ko35.default

sudo -E env "PATH=$PATH" ant build

echo '=================== build finished ========================'



# this test works in RA mode!
#chown -R root /home/seluser
ant test:runone -Dtest.runone=EcaQa28_ServiceManagement
