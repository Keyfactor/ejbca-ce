#!/usr/bin/env bash
# @version $Id$

echo "Performing a restore of EJBCA from previous version"
STARTING_DIRECTORY=$PWD
if [ -z "$EJBCA_HOME" ] ; then
	echo "Please enter EJBCA home directory"
	read EJBCA_HOME
fi
echo "Please enter a working directory (default is /tmp):"
read WORKING_DIRECTORY
if [ "$WORKING_DIRECTORY" = "" ]; then
	WORKING_DIRECTORY="/tmp"
fi
echo "Please enter file to restore from (complete path)"
read BACKUP_FILE
echo "Decrypting backup file"
cd $EJBCA_HOME/dist/clientToolBox
echo "Please input shared library name"
read SHARED_LIBRARY_NAME 
echo "Please input slot number. start with 'i' to indicate index in list"
read SLOT_NUMBER
echo "Please input key alias"
read KEY_ALIAS
./ejbcaClientToolBox.sh PKCS11HSMKeyTool decrypt $SHARED_LIBRARY_NAME $SLOT_NUMBER $BACKUP_FILE $WORKING_DIRECTORY/backup.zip $KEY_ALIAS
cd $WORKING_DIRECTORY
echo "Unzipping $WORKING_DIRECTORY/backup.zip"
unzip -o $WORKING_DIRECTORY/backup.zip
rm -f $WORKING_DIRECTORY/backup.zip
echo "Restoring configuration files"
unzip -o $WORKING_DIRECTORY/conf.zip -d $EJBCA_HOME/conf
rm -f $WORKING_DIRECTORY/conf.zip
unzip -o $WORKING_DIRECTORY/p12.zip -d $EJBCA_HOME/p12
rm -f $WORKING_DIRECTORY/p12.zip
echo "Preparing to restore database"
echo "Please enter your database type [mysql|postgres] (default: mysql):"
read DATABASE_TYPE
echo "Please enter database host address (default: 127.0.0.1):"
read DATABASE_HOST
if [ "$DATABASE_HOST" = "" ]; then 
	DATABASE_HOST="127.0.0.1" 
fi
echo "Please enter database root user (default: root)"
read DATABASE_USER
if [ "$DATABASE_USER" = "" ]; then 
	DATABASE_USER="root"
fi
if [ "$DATABASE_TYPE" = "postgres"  ]; then
	echo "Now restoring Postgres database"
	echo "Please enter location of pg_restore executable (default: /usr/bin)"
	read PGSQL_HOME
	if [ "$PGSQL_HOME" = "" ]; then 
		PGSQL_HOME="/usr/bin"
		#PGSQL_HOME="/Library/PostgreSQL/9.0/bin"
	fi
	$PGSQL_HOME/pg_restore -c -W -h$DATABASE_HOST -U$DATABASE_USER -d ejbca $WORKING_DIRECTORY/dbdump.sql
else
	echo "Please enter database port (default: 3306):"
	read DATABASE_PORT
	if [ "$DATABASE_PORT" = "" ]; then 
		DATABASE_PORT="3306"
	fi
	
	echo "Please enter location of mysql executable (default: /usr/bin)"
	read MYSQL_HOME
	if [ "$MYSQL_HOME" = "" ]; then 
		MYSQL_HOME="/usr/bin"
	fi
	echo "Now restoring MySQL database"
	$MYSQL_HOME/mysql -h$DATABASE_HOST --port=$DATABASE_PORT -u$DATABASE_USER -p ejbca -e "source $WORKING_DIRECTORY/dbdump.sql"
fi
echo "Removing temporary file dbdump.sql"
rm -f $WORKING_DIRECTORY/dbdump.sql
cd $STARTING_DIRECTORY