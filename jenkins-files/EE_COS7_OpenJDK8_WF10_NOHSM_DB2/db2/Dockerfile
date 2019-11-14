FROM ibmcom/db2:11.5.0.0a

LABEL description="ibmcom/db2"

ENV LICENSE=accept
ENV DB2INSTANCE=db2inst1
ENV DB2INST1_PASSWORD=db2inst1
ENV DBNAME=ejbca

RUN mkdir /var/custom
COPY db2_init_ejbca.sh /var/custom
RUN chmod a+x /var/custom/db2_init_ejbca.sh
COPY create-tables-ejbca-db2.sql /var/custom/
COPY create-index-ejbca.sql /var/custom/


EXPOSE 50000
