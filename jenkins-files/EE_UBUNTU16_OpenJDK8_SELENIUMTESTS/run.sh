#!/bin/sh

cp -R /app/svq3ko35.default /home/seluser/.mozilla/firefox/
cp /app/profiles.ini /home/seluser/.mozilla/firefox/profiles.ini

/opt/bin/entry_point.sh &

sleep 10

# ant test:runone -Dtest.runone=EcaQa12_CPManagement

# this test works in RA mode!
ant test:runone -Dtest.runone=EcaQa28_ServiceManagement

sleep 1000000