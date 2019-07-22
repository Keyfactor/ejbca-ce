#!/bin/sh

/opt/mssql/bin/sqlservr &

echo 'Waiting for MS SQL Server 2017 warms-up...'
sleep 90s

echo 'Initializing the database after 90 seconds...'
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P MyEjbcaPass1100 -Q "CREATE DATABASE ejbca"

