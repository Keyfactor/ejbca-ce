@echo off
REM $Id$
:BEGIN
SET STARTING_DIRECTORY=%cd%
IF NOT DEFINED EJBCA_HOME (GOTO DEFINE_EJBCA_HOME)
SET WORKING_DIRECTORY=
SET /P WORKING_DIRECTORY=Please enter a working directory (default is C:\tmp): %=%
IF "%WORKING_DIRECTORY%"=="" SET WORKING_DIRECTORY=C:\tmp
ECHO Using directory %WORKING_DIRECTORY%
SET BACKUP_FILE=
SET /P BACKUP_FILE=Please enter file to restore from (complete path): %=%
ECHO Decrypting backup file %BACKUP_FILE%
SET SHARED_LIBRARY_NAME=
SET /P SHARED_LIBRARY_NAME="Please input shared library name:" %=%
SET SLOT_NUMBER=
SET /P SLOT_NUMBER="Please input slot number. start with 'i' to indicate index in list:" %=%
SET KEY_ALIAS=
SET /P KEY_ALIAS="Please input key alias:" %=%
%EJBCA_HOME%\dist\clientToolBox\ejbcaClientToolBox.bat PKCS11HSMKeyTool decrypt "%SHARED_LIBRARY_NAME%" %SLOT_NUMBER% "%BACKUP_FILE%" "%WORKING_DIRECTORY%\backup.jar" %KEY_ALIAS%
ECHO "Unzipping %WORKING_DIRECTORY%\backup.jar"
cd %WORKING_DIRECTORY%
jar xf %WORKING_DIRECTORY%\backup.jar
DEL %WORKING_DIRECTORY%\backup.jar
ECHO "Restoring configuration files"
cd %EJBCA_HOME%\conf
jar xf %WORKING_DIRECTORY%\conf.jar 
DEL %WORKING_DIRECTORY%\conf.jar
cd %EJBCA_HOME%\p12
jar xf %WORKING_DIRECTORY%\p12.jar
DEL %WORKING_DIRECTORY%\p12.jar
ECHO Preparing to restore database
SET DATABASE_TYPE=
SET /P DATABASE_TYPE="Please enter database type [mysql|postgres] (default: mysql):" %=%
IF "%DATABASE_TYPE%"=="" SET DATABASE_TYPE=mysql
ECHO Using database type %DATABASE_TYPE%
SET DATABASE_HOST=
SET /P DATABASE_HOST="Please enter database host address (default: 127.0.0.1):" %=%
IF "%DATABASE_HOST%"=="" SET DATABASE_HOST=127.0.0.1
SET DATABASE_USER=
SET /P DATABASE_USER="Please enter database root user (default: root):"  %=%
IF "%DATABASE_USER%"=="" SET DATABASE_USER=root
IF "%DATABASE_TYPE%"=="mysql" GOTO RESTOREDATABASE_MYSQL
IF "%DATABASE_TYPE%"=="postgres" GOTO RESTOREDATABASE_POSTGRES
:POSTDATABASERESTORE
DEL %WORKING_DIRECTORY%\dbdump.sql
GOTO END
:DEFINE_EJBCA_HOME
SET EJBCA_HOME=
SET /P EJBCA_HOME=EJBCA_HOME not set, please define: %=%
GOTO BEGIN
:RESTOREDATABASE_MYSQL
SET DATABASE_PORT=
SET /P DATABASE_PORT="Please enter database port (default: 3306):" %=%
IF "%DATABASE_PORT%"=="" SET DATABASE_PORT=3306
SET MYSQL_HOME=
SET /P MYSQL_HOME="Please enter location of mysql executable (default: C:\Program Files\MySQL\MySQL Server 5.1\bin)
IF "%MYSQL_HOME%"=="" SET MYSQL_HOME=C:\Program Files\MySQL\MySQL Server 5.1\bin
ECHO Using %MYSQL_HOME%
ECHO Performing restoration of MYSQL database
"%MYSQL_HOME%\mysql" -h%DATABASE_HOST% --port=%DATABASE_PORT% -u%DATABASE_USER% -p ejbca -e "source "%WORKING_DIRECTORY%\dbdump.sql"
GOTO POSTDATABASERESTORE
:RESTOREDATABASE_POSTGRES
SET PGSQL_HOME=
SET /P PGSQL_HOME="Please enter location of pg_restore executable (default: C:\Program Files\PostgreSQL\9.0\bin):" %=%
IF "%PGSQL_HOME%"=="" SET PGSQL_HOME=C:\Program Files\PostgreSQL\9.0\bin
ECHO Using %PGSQL_HOME%
ECHO Performing restoration of Postgres database
"%PGSQL_HOME%\pg_restore" -c -W -h%DATABASE_HOST% -U%DATABASE_USER% -d ejbca "%WORKING_DIRECTORY%\dbdump.sql"
GOTO POSTDATABASERESTORE
:END
ECHO Restore operation now complete
cd %STARTING_DIRECTORY%