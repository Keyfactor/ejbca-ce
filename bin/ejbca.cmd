@echo off

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
set a=%1
set b=%2
set c=%3
set d=%4
set e=%5
set f=%6
set g=%7
set h=%8
set i=%9
shift
set j=%9
shift
set k=%9
shift
set l=%9
shift
set m=%9
rem echo %a% %b% %c% %d% %e% %f% %g% %h% %i% %j% %k% %l% %m%

"%JAVA_HOME%\bin\java" -jar "%EJBCA_HOME%\dist\ejbca-ejb-cli\ejbca-ejb-cli.jar" %a% %b% %c% %d% %e% %f% %g% %h% %i% %j% %k% %l% %m%

:end
