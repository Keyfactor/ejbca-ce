FROM microsoft/mssql-server-linux:2017-latest

LABEL description="microsoft/mssql-server-linux-ejbca"

ENV ACCEPT_EULA=Y
ENV SA_PASSWORD=MyEjbcaPass1100

ADD entrypoint.sh /opt/
RUN chmod u+x /opt/entrypoint.sh

EXPOSE 1433

ENTRYPOINT /opt/entrypoint.sh
