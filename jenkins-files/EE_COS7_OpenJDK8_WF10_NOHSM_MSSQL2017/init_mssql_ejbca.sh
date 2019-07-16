#!/bin/sh

docker exec -it $DOCKER_NAME_DB /opt/mssql-tools/bin/sqlcmd -S $DOCKER_NAME_NET -U sa -P $DB_PASSWORD<<EOF
sqlcmd -Q "create database ejbca" -o ejbca.log
cat ejbca.log
EOF
