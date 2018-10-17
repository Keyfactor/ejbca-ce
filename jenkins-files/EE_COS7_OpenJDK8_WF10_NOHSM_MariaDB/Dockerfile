FROM jboss/wildfly:10.1.0.Final

USER root

#Create Ant Dir
RUN mkdir -p /opt/ant/

#Download Ant 1.9.8
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

#Updating Path
ENV PATH="${PATH}:${HOME}/bin:${ANT_HOME}/bin"

#Setting environment variables
ENV JAVA_OPTS="-Xms2048m -Xmx2048m -XX:MetaspaceSize=192M -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true"

#Setting Ant Params
ENV ANT_OPTS="-Xms256M -Xmx512M"

#Copy the run script and set execution privileges to it
ADD run.sh /opt/
RUN chmod +x /opt/run.sh

# copy ejbca conf to /opt in the container for runtime-usage
ADD conf /opt/conf
RUN chmod 777 /opt/conf


#copy two stages of standalone.xml file (WildFly config file). They are both needed for different stages of installation
ADD standalone1.xml /opt/standalone1.xml
ADD standalone2.xml /opt/standalone2.xml


# add mariadb driver to deploy folder
ADD mariadb-java-client.jar /opt/jboss/wildfly/standalone/deployments/mariadb-java-client.jar

# Set the working directory to /app
WORKDIR /app/ejbca


CMD ["/opt/run.sh"]
