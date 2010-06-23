@echo off

rem 
rem Bruno Bonfils, <asyd@asyd.net>
rem January 2007
rem 
rem Create a key via a netHSM device 
rem Example:
rem
if "%JAVA_HOME%" == "" (
    echo You must set JAVA_HOME before running the nCipher cli.
    goto end
)

if "%EJBCA_HOME%" == "" (
    echo You must set EJBCA_HOME before running the nCipher cli.
    goto end
)

if "%NFAST_HOME%" == "" (
    echo Warning: NFAST_HOME not set, using default to /opt/nfast
    set NFAST_HOME=\opt\nfast
)

set NFAST_JARS=%NFAST_HOME%\java\classes

rem Add nfast's JARs to classpath
set CLASSES=%NFAST_JARS%\rsaprivenc.jar;%NFAST_JARS%\nfjava.jar;%NFAST_JARS%\kmjava.jar;%NFAST_JARS%\kmcsp.jar;%NFAST_JARS%\jutils.jar

if exist "%EJBCA_HOME%\dist\clientToolBox\clientToolBox.jar" goto exists
	echo You have to build the ClientToolBox before running this command.
	goto end
:exists

@echo on
"%JAVA_HOME%\bin\java" -cp %CLASSES% -jar "%EJBCA_HOME%\dist\clientToolBox\clientToolBox.jar" NCipherHSMKeyTool %1 %2 %3 %4 %5 %6

:end
