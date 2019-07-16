#!/bin/sh

docker exec -it $DOCKER_NAME_DB /opt/mssql-tools/bin/sqlcmd -S $DOCKER_NAME_NET -U sa -P $DB_PASSWORD<<EOF
create database ejbca
go
exit
EOF
