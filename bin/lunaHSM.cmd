@echo off

if "%JAVA_HOME%" == "" (
    echo You must set JAVA_HOME before running the Luna cli.
    goto end
)

if "%EJBCA_HOME%" == "" (
    echo You must set EJBCA_HOME before running the Luna cli.
    goto end
)

"%JAVA_HOME%\bin\java" -cp %EJBCA_HOME%\lib\LunaJCASP.jar;%EJBCA_HOME%\tmp\bin\classes org.ejbca.ui.cli.LunaKeyTool %1 %2 %3 %4 %5 %6
