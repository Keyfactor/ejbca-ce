FROM microsoft/mssql-server-linux:2017-latest

LABEL description="microsoft/mssql-server-linux"

ENV ACCEPT_EULA=Y
ENV SA_PASSWORD=MyEjbcaPass1100
# Latin1-General, case-sensitive, accent-sensitive, kanatype-sensitive, width-sensitive
# UTF-8 > v.2019
ENV MSSQL_COLLATION=Latin1_General_CS_AS_KS_WS

EXPOSE 1433