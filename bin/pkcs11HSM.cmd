@echo off

rem Create a key via a PKCS11 device
rem Example:
rem

if "%JAVA_HOME%" == "" (
    echo You must set JAVA_HOME before running the PKCS#11 cli.
    goto end
)

if "%EJBCA_HOME%" == "" (
    echo You must set EJBCA_HOME before running the PKCS#11 cli.
    goto end
)

if exist "%EJBCA_HOME%\dist\clientToolBox\clientToolBox.jar" goto exists
	echo You have to build the ClientToolBox before running this command.
	goto end
:exists

@echo on
"%JAVA_HOME%\bin\java" -jar "%EJBCA_HOME%\dist\clientToolBox\clientToolBox.jar" PKCS11HSMKeyTool %1 %2 %3 %4 %5 %6

:end
