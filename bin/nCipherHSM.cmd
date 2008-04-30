@echo off

rem 
rem Bruno Bonfils, <asyd@asyd.net>
rem January 2007
rem 
rem Create a key via a netHSM device rem 
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

set CLASSES=%EJBCA_HOME%\lib\bcprov-jdk15.jar
set CLASSES=%CLASSES%;%EJBCA_HOME%\lib\bcmail-jdk15.jar
set CLASSES=%CLASSES%;%EJBCA_HOME%\lib\jline-0.9.94.jar
set CLASSES=%CLASSES%;%EJBCA_HOME%\tmp\bin\classes
rem use this instead if you want build from eclipse
rem CLASSES=$CLASSES:$EJBCA_HOME/out/classes

rem Add nfast's JARs to classpath
set CLASSES=%CLASSES%;%NFAST_JARS%\rsaprivenc.jar;%NFAST_JARS%\nfjava.jar;%NFAST_JARS%\kmjava.jar;%NFAST_JARS%\kmcsp.jar;%NFAST_JARS%\jutils.jar

rem Finally run java
echo "%JAVA_HOME%\bin\java" -cp %CLASSES% org.ejbca.ui.cli.HSMKeyTool %0 %1 com.ncipher.provider.km.nCipherKM com.ncipher.fixup.provider.nCipherRSAPrivateEncrypt nCipher.sworld %2 %3 %4 %5 %6

"%JAVA_HOME%\bin\java" -cp %CLASSES% org.ejbca.ui.cli.HSMKeyTool %0 %1 com.ncipher.provider.km.nCipherKM com.ncipher.fixup.provider.nCipherRSAPrivateEncrypt nCipher.sworld %2 %3 %4 %5 %6