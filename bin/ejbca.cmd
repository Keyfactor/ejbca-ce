@echo off

rem Check that JAVA_HOME is set
if "%JAVA_HOME%" == "" (
    echo You must set JAVA_HOME before running the EJBCA cli.
    goto end
)
    
rem Which command are we running?
set class_name=""
if "%1" == "batch" set class_name=se.anatom.ejbca.batch.BatchMakeP12
if "%1" == "ca" set class_name=se.anatom.ejbca.admin.ca
if "%1" == "jobrunner" set class_name=se.anatom.ejbca.util.JobRunner
if "%1" == "ra" set class_name=se.anatom.ejbca.admin.ra
if "%1" == "setup" set class_name=se.anatom.ejbca.admin.setup
if "%1" == "template" set class_name=se.anatom.ejbca.admin.SVGTemplatePrinter
if %class_name% == "" (
    echo "Usage: %0 [batch|ca|ra|setup|template|jobrunner] options"
	echo For options information, specify a command directive
    goto end
)
rem echo Class name to run is %class_name%

rem J2EE server classpath
set J2EE_DIR=""
set J2EE_CP=""
if not "%JBOSS_HOME%" == ""  ( 
    echo Using JBoss JNDI provider...
    set J2EE_DIR=%JBOSS_HOME%\client
    set J2EE_CP=%JBOSS_HOME%\client\jnp-client.jar;%JBOSS_HOME%\client\jboss-j2ee.jar;%JBOSS_HOME%\client\jbossall-client.jar;%JBOSS_HOME%\client\jboss-client.jar;%JBOSS_HOME%\client\jbosssx-client.jar;%JBOSS_HOME%\client\jboss-common-client.jar
) else if not "%WEBLOGIC_HOME%" == ""  ( 
    echo Using Weblogic JNDI provider...
    set J2EE_DIR=%WEBLOGIC_HOME%\client
    set J2EE_CP=%WEBLOGIC_HOME%\weblogic.jar
) else (
    echo Could not find a valid J2EE server for JNDI provider.
    echo Specify a JBOSS_HOME or WEBLOGIC_HOME environment variable
    goto end
)
rem echo J2EE directory is %J2EE_DIR%

rem library classpath
set EJBCA_HOME=..
set EJBCA_CP=%EJBCA_HOME%\lib\ldap.jar;%EJBCA_HOME%\lib\log4j-1.2.7.jar;%EJBCA_HOME%\lib\bcprov-jdk14-124.jar;%EJBCA_HOME%\lib\bcmail-jdk14-124.jar
set CP=%EJBCA_HOME%\bin\classes

rem check that we have built the classes
if not exist %CP% (
    echo You must build EJBCA before using the cli, use 'ant'.
    goto end
)

rem Due to short limit of windows command line, we can not use the below to
rem automgically construct the classpath, as we can du with unices.
rem 
rem SETLOCAL ENABLEDELAYEDEXPANSION
rem IF ERRORLEVEL 1 echo Unable to enable extensions
rem for %%i in (%J2EE_DIR%\*.jar) do set JBOSS_CP=%%i;!JBOSS_CP!
rem for %%i in (%EJBCA_HOME%\lib\*.jar) do set CP=%%i;!CP!
rem for %%i in (%EJBCA_HOME%\dist\*.jar) do set CP=%%i;!CP!

set CLASSPATH=%J2EE_CP%;%EJBCA_CP%;%CP%
rem echo %CLASSPATH%
%JAVA_HOME%\bin\java -cp %CLASSPATH% %class_name% %2 %3 %4 %5 %6 %7 %8 %9

:end
