#!/usr/bin/env bash
# @version $Id$

echo "Performing a restore of EJBCA from previous version"
STARTING_DIRECTORY=$PWD
if [ -z "$EJBCA_HOME" ] ; then
	EJBCA_FILE="$0" 
	EJBCA_HOME=`echo $(dirname $EJBCA_FILE)`
	cd $EJBCA_HOME
	cd ../..
	EJBCA_HOME=`pwd`
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
#./ejbcaClientToolBox.sh PKCS11HSMKeyTool decrypt $SHARED_LIBRARY_NAME $SLOT_NUMBER BACKUP_FILE $WORKING_DIRECTORY/backup.zip KEY_ALIAS
cd $WORKING_DIRECTORY
echo "Unzipping $WORKING_DIRECTORY/backup.zip"
unzip -o $WORKING_DIRECTORY/backup.zip
#rm -f $WORKING_DIRECTORY/backup.zip
echo "Restoring configuration files"
unzip -o $WORKING_DIRECTORY/conf.zip -d $EJBCA_HOME/conf
rm -f $WORKING_DIRECTORY/conf.zip
rm -f $WORKING_DIRECTORY/p12.zip
unzip -o $WORKING_DIRECTORY/p12.zip -d $EJBCA_HOME/p12
echo "Preparing to restore database"
echo "Please enter your database type [mysql|postgres] (default: mysql):"
read DATABASE_TYPE
echo "Please enter database host address (default: 127.0.0.1):"
read DATABASE_HOST
if [ "$DATABASE_HOST" = "" ]; then 
	DATABASE_HOST="127.0.0.1"
fi
echo "Please enter database root user (default: root)"
read database_user
if [ "$database_user" = "" ]; then 
	database_user="root"
fi
if [ "$DATABASE_TYPE" = "postgres"  ]; then
	echo "Now restoring Postgres database"
else
	echo "Please enter database port (default: 3306):"
	read DATABASE_PORT
	if [ "$DATABASE_PORT" = "" ]; then 
		DATABASE_PORT="3306"
	fi
	
	echo "Please enter location of mysql executable (default: /usr/local/mysql/bin)"
	read mysql_home
	if [ "$mysql_home" = "" ]; then 
		mysql_home="/usr/local/mysql/bin"
	fi
	echo "Now restoring MySQL database"
	$mysql_home/mysql -h$DATABASE_HOST --port=$DATABASE_PORT -u$database_user -p ejbca -e "source $WORKING_DIRECTORY/dbdump.sql"
fi

rm -f $WORKING_DIRECTORY/dbdump.sql
cd $STARTING_DIRECTORY