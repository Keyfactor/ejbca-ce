@echo off
rem ----
rem $Id: deploy.cmd,v 1.6 2002-03-10 20:06:06 anatom Exp $
rem
rem Deploy script for EJBCA
rem
rem Copies all files to their respective location. Also checks
rem that the dependant files are properly installed.
rem
rem ----

rem Check for proper settings of environment variables
if "%JBOSS_HOME%" == ""  goto error

rem Check for dependencies
if exist %JBOSS_HOME%\lib\ext\jce-jdk13-111.jar goto deploy

:install
xcopy lib\jce-jdk13-111.jar %JBOSS_HOME%\lib\ext /Q /Y
xcopy lib\ldap.jar %JBOSS_HOME%\lib\ext /Q /Y
echo Copied jce-jdk13-111.jar and ldap.jar to %JBOSS_HOME%\lib\ext. JBoss must be restared.

:deploy
xcopy dist\*.war %JBOSS_HOME%\deploy /Q /Y
xcopy dist\*.jar %JBOSS_HOME%\deploy /Q /Y
echo Deployed jar- and war-files in %JBOSS_HOME%\deploy
goto end

:error 
echo JBOSS_HOME must be set

:end

