#!/bin/sh

txt2html README > README.html
txt2html SECURITY > SECURITY.html
txt2html --nolink FAQ > FAQ.html
txt2html --nolink HOWTO-LDAP.txt > HOWTO-LDAP.html
#txt2html --nolink HOWTO-mysql.txt > HOWTO-mysql.html
#txt2html --nolink HOWTO-postgresql.txt > HOWTO-postgresql.html
txt2html --nolink HOWTO-database.txt > HOWTO-database.html
