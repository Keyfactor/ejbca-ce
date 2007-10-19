@echo off

rem 
rem  JBoss Control Script
rem 

rem make java is on your path
set JAVAPTH=%APPSRV_HOME%\bin

rem define the classpath for the shutdown class
set JBOSSCP=%APPSRV_HOME%\bin\shutdown.jar:%APPSRV_HOME%\client\jnet.jar

rem define the script to use to start jboss
rem JBOSSSH=${JBOSSSH:-"$APPSRV_HOME/bin/run.sh -c all"}

if "%1" == "-np" (
	set JBOSSSH=%APPSRV_HOME%\bin\run.bat
) else (
	set JBOSSSH=%NFAST_HOME%\bin\preload %APPSRV_HOME%\bin\run.bat
)

set CMD_START=%JBOSSSH%
set CMD_STOP=java -classpath %JBOSSCP% org.jboss.Shutdown --shutdown

set NFAST_JAR=%NFAST_HOME%\java\classes
set JBOSS_CLASSPATH=%NFAST_JAR%\kmcsp.jar;%NFAST_JAR%\kmjava.jar;%NFAST_JAR%\nfjava.jar;%NFAST_JAR%\rsaprivenc.jar
rem export JAVA_OPTS="-server -Xms128m -Xmx512m -Dsun.rmi.dgc.client.gcInterval=3600000 -Dsun.rmi.dgc.server.gcInterval=3600000 -DCKNFAST_LOADSHARING=0 -DJCECSP_DEBUG=229 -DJCECSP_DEBUGFILE=jceLog"

set PATH=%PATH%;%JAVAPTH%

echo CMD_START = %CMD_START%

if "%1" == "start" (
	%CMD_START% %2 %3 %4 %5 %6 %7 %8
)

if "%1" == "-np" (
	%CMD_START% %3 %4 %5 %6 %7 %8 %9
)

if "%1" == "stop" (
	%CMD_STOP%
)

if "%1" == "" (
    echo "usage: %0% ([-np] start|stop|help)"
    echo " -np   Run without pre-load"
)
