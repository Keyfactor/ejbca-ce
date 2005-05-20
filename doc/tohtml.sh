#!/bin/sh

# Small scripot that uses txt2html to create simple html pages from ordinary text files.

echo building README.html
txt2html README > README.html
echo building SECURITY.html
txt2html SECURITY > SECURITY.html
echo building FAQ.html
txt2html FAQ > FAQ.html
echo building HOWTO-LDAP.html
txt2html howto/HOWTO-LDAP.txt > HOWTO-LDAP.html
echo building HOWTO-database.html
txt2html howto/HOWTO-database.txt > HOWTO-database.html
echo building HOWTO-Appserver.html
txt2html howto/HOWTO-Appserver.txt > HOWTO-Appserver.html
