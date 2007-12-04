#!/bin/bash

SQLUSER=ejbca
SQLHOST=localhost
SQLDATABASE=ejbca
SQLFILE=mysql-database-privileges.sql

echo "Accessing database \"$SQLDATABASE\" as user \"$SQLUSER\"."
COMMAND=`echo "show tables" | mysql -u $SQLUSER -p $SQLDATABASE | grep -v Tables_in_ejbca`
echo "revoke ALL on $SQLDATABASE.* from '$SQLUSER'@'$SQLHOST';" > $SQLFILE
for table in $COMMAND; do echo "revoke ALL on $SQLDATABASE.$table from '$SQLUSER'@'$SQLHOST';"; done >> $SQLFILE
for table in $COMMAND; do echo "grant ALL on $SQLDATABASE.$table to '$SQLUSER'@'$SQLHOST';"; done >> $SQLFILE
for table in $COMMAND; do echo "revoke ALL on $SQLDATABASE.$table from '$SQLUSER'@'$SQLHOST';" | grep -i ProtectedLog | grep -iv ProtectedLogExportData; done >> $SQLFILE
for table in $COMMAND; do echo "grant SELECT,INSERT,CREATE on $SQLDATABASE.$table to '$SQLUSER'@'$SQLHOST';" | grep -i ProtectedLog | grep -iv ProtectedLogExportData; done >> $SQLFILE
for table in $COMMAND; do echo "revoke ALL on $SQLDATABASE.$table from '$SQLUSER'@'$SQLHOST';" | grep -i LogEntryData; done >> $SQLFILE
for table in $COMMAND; do echo "grant SELECT,INSERT,CREATE on $SQLDATABASE.$table to '$SQLUSER'@'$SQLHOST';" | grep -i LogEntryData; done >> $SQLFILE
