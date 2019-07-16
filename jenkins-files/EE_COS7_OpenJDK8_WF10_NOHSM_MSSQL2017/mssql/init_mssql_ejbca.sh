#!/bin/sh

docker exec -it $DOCKER_NAME_DB /opt/mssql-tools/bin/sqlcmd -U sa -P $DB_PASSWORD -Q 'CREATE DATABASE ejbca'
