FROM ibmcom/db2:11.5.0.0a

LABEL description="ibmcom/db2-11.5.0.0a-ejbca"

ENV LICENSE=accept
ENV DB2INSTANCE=db2inst1
ENV DB2INST1_PASSWORD=db2inst1
ENV DBNAME=ejbca

# Create a custom folder and copy initialization script into it
# The container executes all the scripts of this folder after MSSQL setup
RUN mkdir /var/custom
COPY db2_init_ejbca.sh /var/custom
RUN chmod a+x /var/custom/db2_init_ejbca.sh

EXPOSE 50000