@echo off
SetLocal EnableDelayedExpansion 

rem Check that JAVA_HOME is set
if "%JAVA_HOME%" == "" (
    echo You must set JAVA_HOME before running the EJBCA cli.
    goto end
)
    
set EJBCA_HOME=..
rem It must work to call both as bin\ejbca.cmd or from within bin
if not exist ejbca.cmd set EJBCA_HOME=.

rem check that we have built the JAR
if not exist %EJBCA_HOME%\dist\ejbca-ejb-cli\ejbca-ejb-cli.jar (
    echo You must build EJBCA before using the cli, use 'ant'.
    goto end
)

For /f "tokens=1,2 delims==" %%a in ("%EJBCA_HOME%\conf\ejbca.properties") Do (
	If "%%a"=="appserver.home" set APPSRV_HOME=%%b
)

rem Fixup arguments, we have to do this since windows normally only 
rem supports %1-%9 as command line arguments
FOR %%A IN (%*) DO (
    set args=!args! %%A
) 
rem echo %args%

"%JAVA_HOME%\bin\java" -jar "%EJBCA_HOME%\dist\ejbca-ejb-cli\ejbca-ejb-cli.jar" %args%

:end