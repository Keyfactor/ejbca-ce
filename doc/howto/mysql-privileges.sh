#!/bin/bash

# This script will create an SQL file that you can inspect and apply to your database.
# apply with 'mysql -u root -p < mysql-database-privileges.sql'

# root user used to create this script
SQLROOTUSER=root
# The user that we should revoke and grant privileges from
SQLUSER=ejbca
SQLHOST=localhost
# The database that SQLUSER will have access to
SQLDATABASE=ejbca
# The output file where resulting the sql script will be written 
SQLFILE=mysql-database-privileges.sql

echo "Accessing database \"$SQLDATABASE\" as user \"$SQLROOTUSER\"."
COMMAND=`echo "show tables" | mysql -u $SQLROOTUSER -p $SQLDATABASE | grep -v Tables_in_ejbca`
echo "revoke ALL PRIVILEGES, GRANT OPTION from '$SQLUSER'@'$SQLHOST';" > $SQLFILE
for table in $COMMAND; do echo "grant SELECT,INSERT,UPDATE,DELETE,INDEX on $SQLDATABASE.$table to '$SQLUSER'@'$SQLHOST';"; done >> $SQLFILE
for table in $COMMAND; do echo "revoke ALL on $SQLDATABASE.$table from '$SQLUSER'@'$SQLHOST';" | grep -i ProtectedLog | grep -iv ProtectedLogExportData; done >> $SQLFILE
for table in $COMMAND; do echo "grant SELECT,INSERT on $SQLDATABASE.$table to '$SQLUSER'@'$SQLHOST';" | grep -i ProtectedLog | grep -iv ProtectedLogExportData; done >> $SQLFILE
for table in $COMMAND; do echo "revoke ALL on $SQLDATABASE.$table from '$SQLUSER'@'$SQLHOST';" | grep -i LogEntryData; done >> $SQLFILE
for table in $COMMAND; do echo "grant SELECT,INSERT on $SQLDATABASE.$table to '$SQLUSER'@'$SQLHOST';" | grep -i LogEntryData; done >> $SQLFILE
