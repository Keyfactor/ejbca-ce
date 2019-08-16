FROM jboss/wildfly:10.1.0.Final
ARG DB_DRIVER_MODULE_PATH

USER root

# Create Ant Dir
RUN mkdir -p /opt/ant/

# Download Ant 1.9.8
ENV ANT_HOME /opt/ant/apache-ant-1.9.8
ENV ANT_SHA1 ca31bd42c27f7e63cccb219ee59930fdc943ca82

RUN cd $HOME \
    && curl -O http://archive.apache.org/dist/ant/binaries/apache-ant-1.9.8-bin.tar.gz \
    && sha1sum apache-ant-1.9.8-bin.tar.gz | grep $ANT_SHA1 \
    && tar xf apache-ant-1.9.8-bin.tar.gz \
    && mv $HOME/apache-ant-1.9.8 $ANT_HOME \
    && rm apache-ant-1.9.8-bin.tar.gz \
    && chown -R jboss:0 ${ANT_HOME} \
    && chmod -R g+rw ${ANT_HOME}

# Updating Path
ENV PATH="${PATH}:${HOME}/bin:${ANT_HOME}/bin"
# Setting environment variables
ENV JAVA_OPTS="-Xms2048m -Xmx2048m -XX:MetaspaceSize=192M -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true"
# Setting Ant Params
ENV ANT_OPTS="-Xms256M -Xmx512M"

# Copy run scripts and set execution privileges
ADD env.sh /opt/
RUN chmod a+x /opt/env.sh
ADD run.sh /opt/
RUN chmod a+x /opt/run.sh

# Copy two stages of standalone.xml file. They are both needed for different stages of installation.
ADD standalone1.xml /opt/standalone1.xml
ADD standalone2.xml /opt/standalone2.xml

# Add a database module with driver or copy the driver to deployment folder
ADD module.xml /opt/module.xml
ADD dbdriver.jar /opt/dbdriver.jar

# Create deployments folder for db driver if any
RUN mkdir -p /opt/deployments/

RUN if [ "x$DB_DRIVER_MODULE_PATH" != "xx" ] ; then mkdir -p /opt/jboss/wildfly/modules/system/layers/base/${DB_DRIVER_MODULE_PATH} ; fi
RUN if [ "x$DB_DRIVER_MODULE_PATH" != "xx" ] ; then cp /opt/module.xml /opt/jboss/wildfly/modules/system/layers/base/${DB_DRIVER_MODULE_PATH}/ ; fi
RUN if [ "x$DB_DRIVER_MODULE_PATH" != "xx" ] ; then cp /opt/dbdriver.jar /opt/jboss/wildfly/modules/system/layers/base/$DB_DRIVER_MODULE_PATH/ ; else cp /opt/dbdriver.jar /opt/deployments/ ; fi

# Fix permissions (1001 is the jenkins user)
RUN chown -R 1001:1001 /opt/jboss/wildfly
USER 1001:1001

# Set the working directory to /app
WORKDIR /app/ejbca

EXPOSE 4447
EXPOSE 8080
EXPOSE 8442
EXPOSE 8443
EXPOSE 9990

CMD ["/opt/run.sh"]
