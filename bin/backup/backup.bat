REM $Id$

@echo off 
:BEGIN
IF NOT DEFINED EJBCA_HOME (GOTO DEFINE_EJBCA_HOME)
SET WORKING_DIRECTORY=
SET /P WORKING_DIRECTORY=Please enter a working directory (default is C:\tmp): %=%
IF "%WORKING_DIRECTORY%"=="" SET WORKING_DIRECTORY=C:\tmp
ECHO Using directory %WORKING_DIRECTORY%
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
IF "%DATABASE_TYPE%"=="mysql" GOTO DUMPDATABASE_MYSQL
IF "%DATABASE_TYPE%"=="postgres" GOTO DUMPDATABASE_POSTGRES
:POSTDATABASEDUMP
ECHO Archiving conf directory (using JAR)
jar cfM %WORKING_DIRECTORY%\conf.jar %EJBCA_HOME%\conf
ECHO Archiving p12 directory (using JAR)
jar cfM %WORKING_DIRECTORY%\p12.jar %EJBCA_HOME%\p12
ECHO Archiving backup file (using JAR)
jar cfM %WORKING_DIRECTORY%\backup.jar %WORKING_DIRECTORY%\p12.jar %WORKING_DIRECTORY%\conf.jar %WORKING_DIRECTORY%\dbdump.sql
DEL %WORKING_DIRECTORY%\p12.jar
DEL %WORKING_DIRECTORY%\conf.jar
DEL %WORKING_DIRECTORY%\dbdump.sql
SET TIMESTAMP=%date%_%time%
ECHO Now encrypting backup.jar into backup-%TIMESTAMP%.backup
SET SHARED_LIBRARY_NAME=
SET /P SHARED_LIBRARY_NAME="Please input shared library name:" %=%
SET SLOT_NUMBER=
SET /P SLOT_NUMBER="Please input slot number. start with 'i' to indicate index in list:" %=%
SET KEY_ALIAS=
SET /P KEY_ALIAS="Please input key alias:" %=%
%EJBCA_HOME%\dist\clientToolBox\ejbcaClientToolBox.bat PKCS11HSMKeyTool encrypt %SHARED_LIBRARY_NAME% %SLOT_NUMBER% %WORKING_DIRECTORY%\backup.jar %WORKING_DIRECTORY%\backup-%TIMESTAMP%.backup %KEY_ALIAS%
DEL %WORKING_DIRECTORY%\backup.jar
GOTO END
:DEFINE_EJBCA_HOME
SET EJBCA_HOME=
SET /P EJBCA_HOME=EJBCA_HOME not set, please define: %=%
GOTO BEGIN
:DUMPDATABASE_MYSQL
SET DATABASE_PORT=
SET /P DATABASE_PORT="Please enter database port (default: 3306):" %=%
IF "%DATABASE_PORT%"=="" SET DATABASE_PORT=3306
SET MYSQL_HOME=
SET /P MYSQL_HOME="Please enter location of mysqldmp executable (default: C:\Program Files (x86)\MySQL\MySQL Server 5.1\bin)
IF "%MYSQL_HOME%"=="" SET MYSQL_HOME="C:\Program Files (x86)\MySQL\MySQL Server 5.1\bin"
ECHO Using %MYSQL_HOME%
ECHO Performing dump of MYSQL database
%MYSQL_HOME%\mysqldump --add-drop-table -h%DATABASE_HOST% --port=%DATABASE_PORT% -u%DATABASE_USER% -p ejbca -r %WORKING_DIRECTORY%/dbdump.sql
GOTO POSTDATABASEDUMP
:DUMPDATABASE_POSTGRES
SET PGSQL_HOME=
SET /P PGSQL_HOME="Please enter location of pg_restore executable (default: C:\Program Files\PostgreSQL\9.0\bin):" %=%
IF "%PGSQL_HOME%"=="" SET PGSQL_HOME=C:\Program Files\PostgreSQL\9.0\bin
ECHO Using %PGSQL_HOME%
ECHO Performing dump of Postgres database
%PGSQL_HOME%/pg_dump -Fc -W -h%DATABASE_HOST% -U%DATABASE_USER% -b ejbca -f %WORKING_DIRECTORY%/dbdump.sql
GOTO POSTDATABASEDUMP
:END