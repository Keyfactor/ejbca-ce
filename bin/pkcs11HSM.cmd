@echo off

rem Create a key via a PKCS11 device
rem Example:
rem

if "%JAVA_HOME%" == "" (
    echo You must set JAVA_HOME before running the EJBCA cli.
    goto end
)

if "%EJBCA_HOME%" == "" (
    echo You must set EJBCA_HOME before running the nCipher cli.
    goto end
)

set CLASSES=%EJBCA_HOME%\lib\bcprov-jdk15.jar
set CLASSES=%CLASSES%;%EJBCA_HOME%\lib\bcmail-jdk15.jar
set CLASSES=%CLASSES%;%EJBCA_HOME%\lib\cert-cvc.jar
set CLASSES=%CLASSES%;%EJBCA_HOME%\lib\jline-0.9.94.jar
set CLASSES=%CLASSES%;%EJBCA_HOME%\lib\log4j.jar
set CLASSES=%CLASSES%;%EJBCA_HOME%\lib\commons-lang-2.4.jar
set CLASSES=%CLASSES%;%EJBCA_HOME%\tmp\bin\clientToolBox-classes
rem use this instead if you want build from eclipse
rem CLASSES=$CLASSES:$EJBCA_HOME/out/classes

rem Finally run java

rem Finally run java
echo "%JAVA_HOME%\bin\java" -cp %CLASSES% org.ejbca.ui.cli.ClientToolBox PKCS11HSMKeyTool %1 %2 %3 %4 %5 %6

"%JAVA_HOME%\bin\java" -cp %CLASSES% org.ejbca.ui.cli.ClientToolBox PKCS11HSMKeyTool %1 %2 %3 %4 %5 %6

rem $JAVACMD -cp $CLASSES org.ejbca.ui.cli.ClientToolBox PKCS11HSMKeyTool ${@}
