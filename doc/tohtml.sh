#!/bin/sh

echo building README.html
txt2html README > README.html
echo building SECURITY.html
txt2html SECURITY > SECURITY.html
echo building FAQ.html
txt2html --nolink FAQ > FAQ.html
echo building HOWTO-LDAP.html
txt2html --nolink HOWTO-LDAP.txt > HOWTO-LDAP.html
echo building HOWTO-database.html
#txt2html --nolink HOWTO-mysql.txt > HOWTO-mysql.html
#txt2html --nolink HOWTO-postgresql.txt > HOWTO-postgresql.html
txt2html --nolink HOWTO-database.txt > HOWTO-database.html
echo building HOWTO-weblogic.html
txt2html --nolink HOWTO-Weblogic.txt > HOWTO-Weblogic.html
