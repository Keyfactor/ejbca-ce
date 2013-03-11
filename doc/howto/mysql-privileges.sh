#!/bin/bash

# This script will create an SQL file that you can inspect and apply to your database.
# apply with 'mysql -u root -p < mysql-database-privileges.sql'
#
# Set environment variables to override default in the script, i.e.:
# export SQLUSER=ejbca_user
# export SQLHOST=database.domain.com
# export SQLFILE=ejbca-script.sql
# ./mysql-privileges.sh

# root user used to create this script
SQLROOTUSER=root
# The user@host that we should revoke and grant privileges from
SQLUSER=${SQLUSER:-"ejbca"}
SQLHOST=${SQLHOST:-"localhost"}
# The database that SQLUSER will have access to
SQLDATABASE=${SQLDATABASE:-"ejbca"}
# The output file where resulting the sql script will be written 
SQLFILE=${SQLFILE:-"mysql-database-privileges.sql"}

echo "Accessing database \"$SQLDATABASE\" as user \"$SQLROOTUSER\" to read table metadata, the database will not be modified."
echo "Granting/restricting privileges for user \"$SQLUSER@$SQLHOST\". Writing output to \"$SQLFILE\"."
COMMAND=`echo "show tables" | mysql -u $SQLROOTUSER -p $SQLDATABASE | grep -v Tables_in_ejbca`
echo "revoke ALL PRIVILEGES, GRANT OPTION from '$SQLUSER'@'$SQLHOST';" > $SQLFILE
for table in $COMMAND; do echo "grant SELECT,INSERT,UPDATE,DELETE,INDEX on $SQLDATABASE.$table to '$SQLUSER'@'$SQLHOST';"; done >> $SQLFILE
for table in $COMMAND; do echo "revoke ALL on $SQLDATABASE.$table from '$SQLUSER'@'$SQLHOST';" | grep -i AuditRecordData; done >> $SQLFILE
for table in $COMMAND; do echo "grant SELECT,INSERT on $SQLDATABASE.$table to '$SQLUSER'@'$SQLHOST';" | grep -i AuditRecordData; done >> $SQLFILE
# We need LOCK TABLES permission in order to do a database backup
echo "grant LOCK TABLES on $SQLDATABASE.* to '$SQLUSER'@'$SQLHOST';" >> $SQLFILE
