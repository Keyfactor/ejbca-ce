#!/bin/sh

docker exec -i $DOCKER_NAME_DB /opt/mssql-tools/bin/sqlcmd -S $DOCKER_NAME_DB -U sa -P 'DB_PASSWORD' -Q 'CREATE DATABASE ejbca'

