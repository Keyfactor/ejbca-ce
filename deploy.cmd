@echo off
rem ----
rem $Id: deploy.cmd,v 1.7 2002-04-01 12:10:15 anatom Exp $
rem
rem Deploy script for EJBCA
rem
rem Copies all files to their respective location. Also checks
rem that the dependant files are properly installed.
rem
rem ----

KEYSTORE=src\ca\keyStore\server.p12

rem Check for proper settings of environment variables
if "%JBOSS_HOME%" == ""  goto error

# Install keystore is 'keystore' is given as argument to deploy
if "%1" == "" goto install
if "%1" != "keystore" goto install
if exist %JBOSS_HOME%\conf\server.p12 goto ksexist
xcopy %KEYSTORE% %JBOSS_HOME%\conf /Q /Y
echo Copied %KEYSTORE% to %JBOSS_HOME%\conf.
goto install
:ksexist
echo %KEYSTORE% already exist, no files copied.

rem Install BouncyCastle provider and ldap.jar
:install
if exist %JBOSS_HOME%\lib\ext\jce-jdk13-112.jar goto deploy
xcopy lib\jce-jdk13-112.jar %JBOSS_HOME%\lib\ext /Q /Y
xcopy lib\ldap.jar %JBOSS_HOME%\lib\ext /Q /Y
echo Copied jce-jdk13-112.jar and ldap.jar to %JBOSS_HOME%\lib\ext. JBoss must be restared.

rem Deploy jar and war files
:deploy
xcopy dist\*.war %JBOSS_HOME%\deploy /Q /Y
xcopy dist\*.jar %JBOSS_HOME%\deploy /Q /Y
echo Deployed jar- and war-files in %JBOSS_HOME%\deploy
goto end

:error 
echo JBOSS_HOME must be set

:end

