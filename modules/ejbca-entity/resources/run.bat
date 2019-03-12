@echo off 
REM $Id$

REM Memory settings can be specified using parameters like: -Xms20480m -Xmx20480m -XX:MaxPermSize=384m
java -cp "ejbca-db-cli.jar;endorsed/*" org.ejbca.database.DatabaseCli %1 %2 %3 %4 %5 %6 %7 %8

IF ERRORLEVEL 1 GOTO ERROR

goto END

:ERROR
    echo If you see errors while running the CLI similar to "JDBC Driver class not found" your should copy your JDBC driver JAR to endorsed.

:END
