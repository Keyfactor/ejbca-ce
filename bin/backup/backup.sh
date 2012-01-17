#!/usr/bin/env bash
# @version $Id$

echo "Performing backup of EJBCA"
STARTING_DIRECTORY=$PWD
TIMESTAMP=`date +"%Y-%m-%d_%H:%M"`
if [ -z "$EJBCA_HOME" ] ; then
	echo "Please enter EJBCA home directory"
	read EJBCA_HOME
fi
echo "Please enter a working directory (default is /tmp):"
read WORKING_DIRECTORY
if [ "$WORKING_DIRECTORY" = "" ]; then
	WORKING_DIRECTORY="/tmp"
fi
echo "Using directory $WORKING_DIRECTORY"
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
	echo "Performing dump of postgres database"
	echo "Please enter location of pg_restore executable (default: /usr/local/pgsql/bin)"
	read PGSQL_HOME
	if [ "$PGSQL_HOME" = "" ]; then 
		PGSQL_HOME="/usr/local/pgsql/bin"
		#PGSQL_HOME="/Library/PostgreSQL/9.0/bin"
	fi
	$PGSQL_HOME/pg_dump -Fc -W -h$DATABASE_HOST -U$DATABASE_USER -b ejbca -f $WORKING_DIRECTORY/dbdump.sql
else
	echo "Please enter database port (default: 3306):"
	read DATABASE_PORT
	if [ "$DATABASE_PORT" = "" ]; then 
		DATABASE_PORT="3306"
	fi
	
	echo "Please enter location of mysqldmp executable (default: /usr/local/mysql/bin)"
	read MYSQL_HOME
	if [ "$MYSQL_HOME" = "" ]; then 
		MYSQL_HOME="/usr/local/mysql/bin"
	fi
	echo "Performing dump of mysql database"
	$MYSQL_HOME/mysqldump --add-drop-table -h$DATABASE_HOST --port=$DATABASE_PORT -u$DATABASE_USER -p ejbca -r $WORKING_DIRECTORY/dbdump.sql	
fi
echo "Zipping $EJBCA_HOME/conf"
cd  $EJBCA_HOME/conf
zip -R $WORKING_DIRECTORY/conf . '*.properties'
echo "Zipping $EJBCA_HOME/p12"
cd  $EJBCA_HOME/p12
zip -R $WORKING_DIRECTORY/p12 *
cd $WORKING_DIRECTORY
echo "Zipping temporary files into backup.zip"
zip backup dbdump.sql conf.zip p12.zip
echo "Removing temporary files"
rm -f $WORKING_DIRECTORY/dbdump.sql
rm -f $WORKING_DIRECTORY/conf.zip
rm -f $WORKING_DIRECTORY/p12.zip
echo "Now encrypting backup.zip into backup-$TIMESTAMP.backup"
cd $EJBCA_HOME/dist/clientToolBox
echo "Please input shared library name"
read SHARED_LIBRARY_NAME 
echo "Please input slot number. start with 'i' to indicate index in list"
read SLOT_NUMBER
echo "Please input key alias"
read KEY_ALIAS
./ejbcaClientToolBox.sh PKCS11HSMKeyTool encrypt $SHARED_LIBRARY_NAME $SLOT_NUMBER $WORKING_DIRECTORY/backup.zip $WORKING_DIRECTORY/backup-$TIMESTAMP.backup $KEY_ALIAS
rm -f $WORKING_DIRECTORY/backup.zip
cd $STARTING_DIRECTORY