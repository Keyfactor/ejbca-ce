@echo off

if "%JBOSS_HOME%" == ""  goto error
goto deploy
:error 
echo JBOSS_HOME must be set to deploy automgically.
goto end

:deploy
copy dist\*.war %JBOSS_HOME%\deploy
copy dist\*.jar %JBOSS_HOME%\deploy

:end
echo jce-jdk13-111.jar and ldap.jar must be copied to jboss/lib/ext.